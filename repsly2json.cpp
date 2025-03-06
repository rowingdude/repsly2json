// Compilation command:
// g++ -Wall -Wextra -Werror -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wformat -Werror=format-security -fPIE -pie repsly2json.cpp -o repsly2json -lcurl -ljsoncpp -march=native -mtune=native


#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <chrono>
#include <regex>
#include <iomanip>
#include <stdexcept>
#include <filesystem>
#include <curl/curl.h>
#include <json/json.h>
#include <bits/this_thread_sleep.h>

namespace fs = std::filesystem;

namespace Repsly {
    // Constants
    constexpr size_t MAX_URL_LEN = 512;
    constexpr int DEFAULT_SLEEP_MS = 300;
    constexpr char API_BASE[] = "https://api.repsly.com/v3/export";
    constexpr char DEFAULT_START_DATE[] = "2020-01-01";
    constexpr char DEFAULT_END_DATE[] = "2020-12-31";

    // Pagination types
    enum class PaginationType { NONE, ID, TIMESTAMP, SKIP, DATE_RANGE };

    // Data structures
    struct Endpoint {
        std::string name;
        std::string url_format;
        std::string key;
        PaginationType pagination;
    };

    struct Progress {
        int total = 0;
        int processed = 0;
        std::string status;
    };

    struct PaginationState {
        std::string current_date = DEFAULT_START_DATE;
        std::string end_date = DEFAULT_END_DATE;
        std::string last_id = "0";
        int skip = 0;
        Json::Value meta;
    };

    class Client {
    private:
        CURL* curl_ = nullptr;
        std::string username_;
        std::string password_;
        bool no_pagination_ = false;
        inline static const std::vector<Endpoint> ENDPOINTS = {
            {"pricelists", "%s/pricelists", "Pricelists", PaginationType::NONE},
            {"pricelistsItems", "%s/pricelistsItems/%s", "PricelistsItems", PaginationType::NONE},
            {"representatives", "%s/representatives", "Representatives", PaginationType::NONE},
            {"documentTypes", "%s/documentTypes?includeInactive=true", "DocumentTypes", PaginationType::NONE},
            {"clientnotes", "%s/clientnotes/%s", "ClientNotes", PaginationType::ID},
            {"forms", "%s/forms/%s", "Forms", PaginationType::ID},
            {"dailyworkingtime", "%s/dailyworkingtime/%s", "DailyWorkingTime", PaginationType::ID},
            {"products", "%s/products/%s?includeInactive=true&includeDeleted=true", "Products", PaginationType::ID},
            {"photos", "%s/photos/%s", "Photos", PaginationType::ID},
            {"purchaseorders", "%s/purchaseorders/%s", "PurchaseOrders", PaginationType::ID},
            {"retailaudits", "%s/retailaudits/%s", "RetailAudits", PaginationType::ID},
            {"clients", "%s/clients/%s?includeInactive=true&includeDeleted=true", "Clients", PaginationType::TIMESTAMP},
            {"users", "%s/users/%s?includeInactive=true", "Users", PaginationType::TIMESTAMP},
            {"visits", "%s/visits/%s", "Visits", PaginationType::TIMESTAMP},
            {"visitrealizations", "%s/visitrealizations?modified=%s&skip=%d", "VisitRealizations", PaginationType::SKIP},
            {"visitschedules", "%s/visitschedules/%s/%s", "VisitSchedules", PaginationType::DATE_RANGE}
        };

        static size_t WriteCallback(char* data, size_t size, size_t nmemb, std::string* buffer) {
            buffer->append(data, size * nmemb);
            return size * nmemb;
        }

        std::string constructUrl(const Endpoint& endpoint, const PaginationState& state) const {
            char buffer[MAX_URL_LEN];
            int written = 0;
            if (endpoint.pagination == PaginationType::NONE && endpoint.name == "pricelistsItems" && (state.last_id.empty() || state.last_id == "0")) {
                throw std::runtime_error("pricelistsItems requires a valid pricelistId");
            }
            switch (endpoint.pagination) {
                case PaginationType::SKIP:
                    written = snprintf(buffer, MAX_URL_LEN, endpoint.url_format.c_str(), API_BASE, state.last_id.c_str(), state.skip);
                    break;
                case PaginationType::DATE_RANGE:
                    written = snprintf(buffer, MAX_URL_LEN, endpoint.url_format.c_str(), API_BASE, state.current_date.c_str(), state.end_date.c_str());
                    break;
                case PaginationType::ID:
                case PaginationType::TIMESTAMP:
                    written = snprintf(buffer, MAX_URL_LEN, endpoint.url_format.c_str(), API_BASE, state.last_id.c_str());
                    break;
                case PaginationType::NONE:
                    written = snprintf(buffer, MAX_URL_LEN, endpoint.url_format.c_str(), API_BASE);
                    break;
                default:
                    throw std::runtime_error("Unsupported pagination type");
            }
            if (written < 0 || static_cast<size_t>(written) >= MAX_URL_LEN) {
                throw std::runtime_error("URL construction failed: buffer overflow");
            }
            return std::string(buffer);
        }

        bool updatePagination(const Endpoint& endpoint, const Json::Value& meta, const Json::Value& items, 
                            PaginationState& state, Progress& progress) {
            progress.processed += items.size();
            if (meta.isMember("MetaCollectionResult")) {
                state.meta = meta["MetaCollectionResult"];
            }

            switch (endpoint.pagination) {
                case PaginationType::TIMESTAMP: {
                    if (!meta.isMember("LastTimeStamp")) return false;
                    int64_t new_ts = meta["LastTimeStamp"].asInt64();
                    int64_t current_ts = std::stoll(state.last_id);
                    if (new_ts <= current_ts) return false;
                    state.last_id = std::to_string(new_ts);
                    progress.status = "TS: " + state.last_id;
                    return items.size() > 0;
                }
                case PaginationType::ID: {
                    if (!meta.isMember("FirstID") || !meta.isMember("LastID") || !meta.isMember("TotalCount")) return false;
                    int total_count = meta["TotalCount"].asInt();
                    if (total_count == 0) return false;
                    int64_t new_id = (state.last_id == "0") ? meta["FirstID"].asInt64() : meta["LastID"].asInt64();
                    int64_t current_id = std::stoll(state.last_id);
                    if (new_id <= current_id) return false;
                    state.last_id = std::to_string(new_id);
                    progress.status = "ID: " + state.last_id;
                    return items.size() > 0;
                }
                case PaginationType::SKIP:
                    state.skip += items.size();
                    return items.size() > 0;
                case PaginationType::DATE_RANGE: {
                    std::tm tm{};
                    if (!strptime(state.current_date.c_str(), "%Y-%m-%d", &tm)) return false;
                    tm.tm_mday++;
                    mktime(&tm);
                    char buffer[11];
                    strftime(buffer, sizeof(buffer), "%Y-%m-%d", &tm);
                    state.current_date = buffer;
                    progress.status = "Date: " + state.current_date;
                    return state.current_date <= state.end_date;
                }
                default:
                    return false;
            }
        }

        Json::Value fetchPage(const std::string& url) {
            std::string response;
            curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &response);
            curl_easy_setopt(curl_, CURLOPT_USERNAME, username_.c_str());
            curl_easy_setopt(curl_, CURLOPT_PASSWORD, password_.c_str());

            CURLcode res = curl_easy_perform(curl_);
            if (res != CURLE_OK) {
                std::cerr << "CURL error: " << curl_easy_strerror(res) << " for " << url << std::endl;
                return Json::Value();
            }

            long http_code = 0;
            curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &http_code);
            if (http_code != 200) {
                std::cerr << "HTTP error " << http_code << " for " << url << std::endl;
                return Json::Value();
            }

            Json::Value root;
            Json::Reader reader;
            if (!reader.parse(response, root)) {
                std::cerr << "JSON parse error for " << url << std::endl;
                return Json::Value();
            }
            return root;
        }

        void saveJson(const std::string& filename, const Json::Value& json) {
            fs::create_directory("json_dl");
            std::ofstream file("json_dl/" + filename);
            if (!file) {
                throw std::runtime_error("Failed to open file: json_dl/" + filename);
            }
            file << Json::FastWriter().write(json);
        }

        void reportProgress(const std::string& endpoint, const Progress& p) {
            std::cout << "\r" << std::left << std::setw(20) << endpoint;
            if (p.total > 0) std::cout << "[" << p.processed << "/" << p.total << "] ";
            if (!p.status.empty()) std::cout << p.status;
            std::cout << std::flush;
        }

        Json::Value fetchEndpoint(const Endpoint& endpoint, PaginationState state = {}) {
            Json::Value responses(Json::arrayValue);
            Progress progress;
    
            std::string url = constructUrl(endpoint, state);
            Json::Value page = fetchPage(url);
            if (!page || !page.isMember(endpoint.key)) {
                std::cout << "Endpoint " << endpoint.name << " failed or returned no data\n";
                return Json::Value();
            }
    
            if (page.isMember("MetaCollectionResult")) {
                state.meta = page["MetaCollectionResult"];
            }
    
            if (endpoint.name == "pricelists") {
                for (const auto& pricelist : page[endpoint.key]) {
                    if (pricelist.isMember("pricelistId")) {
                        std::string pricelistId = pricelist["pricelistId"].asString();
                        Endpoint items_endpoint{"pricelistsItems", "%s/pricelistsItems/%s", "PricelistsItems", PaginationType::NONE};
                        PaginationState items_state{DEFAULT_START_DATE, DEFAULT_END_DATE, pricelistId, 0, Json::Value()};
                        Json::Value items = fetchEndpoint(items_endpoint, items_state);
                        if (!items.empty()) {
                            saveJson("repsly_pricelistsItems_" + pricelistId + "_raw.json", items);
                        }
                    }
                }
            } else {
                responses.append(page);
            }
    
            progress.processed += page[endpoint.key].size();
            const auto& meta = page["MetaCollectionResult"];
            if (meta.isMember("TotalCount")) {
                progress.total = meta["TotalCount"].asInt();
            }
    
            // Only paginate if no_pagination_ is false
            if (!no_pagination_ && endpoint.pagination != PaginationType::NONE) {
                bool has_more = true;
                while (has_more) {
                    url = constructUrl(endpoint, state);
                    page = fetchPage(url);
                    if (!page || !page.isMember(endpoint.key)) break;
    
                    if (page.isMember("MetaCollectionResult")) {
                        state.meta = page["MetaCollectionResult"];
                    }
                    responses.append(page);
    
                    const auto& items = page[endpoint.key];
                    const auto& meta_loop = page["MetaCollectionResult"];
                    if (!progress.total && meta_loop.isMember("TotalCount")) {
                        progress.total = meta_loop["TotalCount"].asInt();
                    }
    
                    has_more = updatePagination(endpoint, meta_loop, items, state, progress);
                    reportProgress(endpoint.name, progress);
                    std::this_thread::sleep_for(std::chrono::milliseconds(DEFAULT_SLEEP_MS));
                }
            } else {
                reportProgress(endpoint.name, progress); // Show progress for single call
            }
            std::cout << std::endl;
    
            Json::Value output;
            output["MetaCollectionResult"] = state.meta;
            output["Data"] = responses;
            return output;
        }
    
    public:
        explicit Client(const std::string& config_path, bool no_pagination = false)
            : no_pagination_(no_pagination) { // Initialize the flag
            auto [user, pass] = readConfig(config_path);
            if (user.empty() || pass.empty()) {
                throw std::runtime_error("Invalid credentials in " + config_path);
            }
            username_ = std::move(user);
            password_ = std::move(pass);
            curl_ = curl_easy_init();
            if (!curl_) {
                throw std::runtime_error("Failed to initialize CURL");
            }
        }
    
        ~Client() {
            if (curl_) curl_easy_cleanup(curl_);
        }
    
        Client(const Client&) = delete;
        Client& operator=(const Client&) = delete;
    
        void fetchAll() {
            for (const auto& endpoint : ENDPOINTS) {
                if (endpoint.name == "pricelistsItems") continue; // Skip standalone pricelistsItems
                std::cout << "Processing " << endpoint.name << "...\n";
                Json::Value data = fetchEndpoint(endpoint);
                if (!data.empty()) {
                    saveJson("repsly_" + endpoint.name + "_raw.json", data);
                }
            }
        }
        static std::pair<std::string, std::string> readConfig(const std::string& path) {
            std::ifstream file(path);
            if (!file) {
                throw std::runtime_error("Cannot open config file: " + path);
            }
            std::string line, user, pass;
            std::regex config_pattern(R"((\w+)=\"(.+)\")");
            while (std::getline(file, line)) {
                if (line.empty() || line[0] == '#') continue;
                std::smatch matches;
                if (std::regex_match(line, matches, config_pattern)) {
                    if (matches[1] == "REPSLY_USER") user = matches[2];
                    else if (matches[1] == "REPSLY_PASS") pass = matches[2];
                }
            }
            return {user, pass};
        }
    };
} // namespace Repsly

int main(int argc, char* argv[]) {
    bool no_pagination = false;
    if (argc > 1 && std::string(argv[1]) == "--no-pagination") {
        no_pagination = true;
    }

    try {
        Repsly::Client client("/etc/api/config.conf", no_pagination);
        client.fetchAll();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}

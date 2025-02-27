// g++ -Wall -Wextra -Werror -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wformat -Werror=format-security -fPIE -pie repsly2json.cpp -o repsly2json -lcurl -ljsoncpp -lpqxx -lpq -march=native -mtune=native

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
#include <pqxx/pqxx>
#include <bits/this_thread_sleep.h>

namespace fs = std::filesystem;

namespace Repsly {
    constexpr size_t MAX_URL_LEN = 512;
    constexpr int DEFAULT_SLEEP_MS = 300;
    constexpr char API_BASE[] = "https://api.repsly.com/v3/export";
    constexpr char DEFAULT_START_DATE[] = "2020-01-01";
    constexpr char DEFAULT_END_DATE[] = "2020-12-31";
    static bool debug_enabled = false;
    static std::ofstream debug_log; 

    enum class PaginationType { NONE, ID, TIMESTAMP, SKIP, DATE_RANGE };

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

    // Debug function to write to file
    inline void debug(const std::string& msg) {
        if (debug_enabled && debug_log.is_open()) {
            debug_log << "[DEBUG] " << msg << "\n";
            debug_log.flush();  // Ensure immediate write to file
        }
    }

    class Client {
    private:
        CURL* curl_ = nullptr;
        std::string username_;
        std::string password_;
        bool no_pagination_ = false;
        std::unique_ptr<pqxx::connection> db_conn_;

        inline static const std::vector<Endpoint> ENDPOINTS = {
            {"pricelists", "%s/pricelists", "Pricelists", PaginationType::NONE},
            // We will treat this as a child of pricelists and not keep its own endpoint definition
            //{"pricelistsItems", "%s/pricelistsItems/%s", "PricelistsItems", PaginationType::NONE},
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
            debug("Entering constructUrl for " + endpoint.name);
            char buffer[MAX_URL_LEN];
            int written = 0;
            switch (endpoint.pagination) {
                case PaginationType::SKIP:
                    debug("Constructing SKIP URL with last_id=" + state.last_id + ", skip=" + std::to_string(state.skip));
                    written = snprintf(buffer, MAX_URL_LEN, endpoint.url_format.c_str(), API_BASE, state.last_id.c_str(), state.skip);
                    break;
                case PaginationType::DATE_RANGE:
                    debug("Constructing DATE_RANGE URL with dates " + state.current_date + " to " + state.end_date);
                    written = snprintf(buffer, MAX_URL_LEN, endpoint.url_format.c_str(), API_BASE, state.current_date.c_str(), state.end_date.c_str());
                    break;
                case PaginationType::ID:
                case PaginationType::TIMESTAMP:
                    debug("Constructing ID/TIMESTAMP URL with last_id=" + state.last_id);
                    written = snprintf(buffer, MAX_URL_LEN, endpoint.url_format.c_str(), API_BASE, state.last_id.c_str());
                    break;
                case PaginationType::NONE:
                    debug("Constructing NONE URL, last_id=" + state.last_id);
                    if (endpoint.name == "pricelistsItems") {
                        written = snprintf(buffer, MAX_URL_LEN, endpoint.url_format.c_str(), API_BASE, state.last_id.c_str());
                    } else {
                        written = snprintf(buffer, MAX_URL_LEN, endpoint.url_format.c_str(), API_BASE);
                    }
                    break;
                default:
                    throw std::runtime_error("Unsupported pagination type");
            }
            debug("snprintf returned: " + std::to_string(written));
            if (written < 0 || static_cast<size_t>(written) >= MAX_URL_LEN) {
                throw std::runtime_error("URL construction failed: buffer overflow");
            }
            std::string result(buffer);
            debug("Constructed URL: " + result);
            return result;
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
                debug("CURL failed with error: " + std::string(curl_easy_strerror(res)));
                return Json::Value();
            }
            debug("CURL request succeeded");

            long http_code = 0;
            curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &http_code);
            debug("HTTP response code: " + std::to_string(http_code) + ", response length: " + std::to_string(response.length()));
            if (http_code != 200) {
                std::cerr << "HTTP error " << http_code << " for " << url << std::endl;
                debug("Response content: " + (response.empty() ? "<empty>" : response));
                return Json::Value();
            }

            Json::Value root;
            Json::Reader reader;
            if (!reader.parse(response, root)) {
                std::cerr << "JSON parse error for " << url << std::endl;
                debug("Failed to parse JSON, raw response: " + (response.empty() ? "<empty>" : response));
                return Json::Value();
            }
            debug("JSON parsed successfully, root keys: " + std::to_string(root.getMemberNames().size()));
            return root;
        }

        void saveJson(const std::string& filename, const Json::Value& json, const std::string& endpoint_name) {
            fs::create_directory("json_dl");
            std::ofstream file("json_dl/" + filename);
            if (!file) {
                throw std::runtime_error("Failed to open file: json_dl/" + filename);
            }
            file << Json::FastWriter().write(json);

            try {
                pqxx::work txn(*db_conn_);
                std::string json_str = Json::FastWriter().write(json);
                std::string query = "INSERT INTO repsly.raw_json_data (endpoint_name, data) VALUES ($1, $2)";
                txn.exec_params(query, endpoint_name, json_str);
                txn.commit();
            } catch (const pqxx::sql_error& e) {
                std::cerr << "Database error: " << e.what() << " Query: " << e.query() << std::endl;
                throw std::runtime_error("Failed to upload JSON to database");
            }
        }

        void reportProgress(const std::string& endpoint, const Progress& p) {
            debug("Progress for " + endpoint + ": processed=" + std::to_string(p.processed) + ", total=" + std::to_string(p.total) + ", status=" + p.status);
        }

        Json::Value fetchEndpoint(const Endpoint& endpoint, PaginationState state = {}) {
            debug("Entering fetchEndpoint for " + endpoint.name);
            Json::Value responses(Json::arrayValue);
            Progress progress;
            debug("Initialized responses and progress");

            std::string url = constructUrl(endpoint, state);
            debug("Calling fetchPage with URL: " + url);
            Json::Value page = fetchPage(url);
            std::string failure_note;  // To append failure details for child endpoints
            if (!page || (!page.isMember(endpoint.key) && !page.empty())) {
                debug("Endpoint " + endpoint.name + " failed or returned no data");
                failure_note = "Failed or returned no data";
            } else {
                debug("Fetched page for " + endpoint.name);

                if (page.isMember("MetaCollectionResult")) {
                    state.meta = page["MetaCollectionResult"];
                    debug("MetaCollectionResult found");
                } else {
                    debug("No MetaCollectionResult in response");
                }

                if (endpoint.name == "pricelists") {
                    const Json::Value& pricelists = page[endpoint.key];
                    debug("Processing pricelists, size: " + std::to_string(pricelists.size()));
                    if (pricelists.isNull() || pricelists.empty()) {
                        debug("No pricelists found");
                    } else {
                        bool has_valid_pricelists = false;
                        for (const auto& pricelist : pricelists) {
                            debug("Checking pricelist entry");
                            if (pricelist.isMember("ID")) {
                                has_valid_pricelists = true;
                                std::string pricelistId = std::to_string(pricelist["ID"].asInt());
                                debug("Found pricelist ID: " + pricelistId);

                                Endpoint items_endpoint{"pricelistsItems", "%s/pricelistsItems/%s", "PricelistsItems", PaginationType::NONE};
                                PaginationState items_state{
                                    .current_date = DEFAULT_START_DATE,
                                    .end_date = DEFAULT_END_DATE,
                                    .last_id = pricelistId,
                                    .skip = 0,
                                    .meta = Json::Value()
                                };
                                debug("Fetching pricelistsItems for ID: " + pricelistId);
                                Json::Value items = fetchEndpoint(items_endpoint, items_state);
                                if (!items.empty()) {
                                    debug("Saving pricelistsItems for ID " + pricelistId);
                                    saveJson("repsly_pricelistsItems_" + pricelistId + "_raw.json", items, "pricelistsItems");
                                } else {
                                    debug("No items returned for pricelist ID " + pricelistId);
                                    failure_note = "(pricelistsItems failed for ID " + pricelistId + ")";
                                }
                            } else {
                                debug("Pricelist entry has no ID");
                            }
                        }
                        if (!has_valid_pricelists) {
                            debug("No pricelists with ID found");
                        }
                    }
                    responses.append(page);
                } else {
                    responses.append(page);
                }

                progress.processed += page[endpoint.key].size();
                const auto& meta = page["MetaCollectionResult"];
                if (meta.isMember("TotalCount")) {
                    progress.total = meta["TotalCount"].asInt();
                    debug("TotalCount: " + std::to_string(progress.total));
                }

                if (!no_pagination_ && endpoint.pagination != PaginationType::NONE) {
                    bool has_more = true;
                    while (has_more) {
                        url = constructUrl(endpoint, state);
                        page = fetchPage(url);
                        if (!page || (!page.isMember(endpoint.key) && !page.empty())) break;

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
                    reportProgress(endpoint.name, progress);
                }
            }

            std::cout << "Processed " << std::left << std::setw(20) << endpoint.name;
            if (!failure_note.empty()) {
                std::cout << "Failed " << failure_note;
            } else if (progress.total > 0) {
                std::cout << "[" << progress.processed << "/" << progress.total << "] ";
                if (!progress.status.empty()) std::cout << progress.status;
            } else {
                std::cout << "OK";
            }
            std::cout << std::endl << std::flush;

            debug("Exiting fetchEndpoint for " + endpoint.name);
            Json::Value output;
            output["MetaCollectionResult"] = state.meta;
            output["Data"] = responses;
            return output;
        }

    public:
        explicit Client(const std::string& config_path, bool no_pagination = false)
            : no_pagination_(no_pagination) {
            debug("Initializing Client");
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
            debug("CURL initialized");

            std::string db_config = "dbname=repsly_data user=repsly_app_user password=secure_password_123 host=localhost port=5432";
            try {
                db_conn_ = std::make_unique<pqxx::connection>(db_config);
                if (!db_conn_->is_open()) {
                    throw std::runtime_error("Failed to connect to database");
                }
                debug("Database connection established");
            } catch (const std::exception& e) {
                throw std::runtime_error("Database connection error: " + std::string(e.what()));
            }
        }

        ~Client() {
            if (curl_) curl_easy_cleanup(curl_);
            if (debug_enabled && debug_log.is_open()) debug_log.close();
        }

        Client(const Client&) = delete;
        Client& operator=(const Client&) = delete;

        void fetchAll() {
            debug("Starting fetchAll");
            for (const auto& endpoint : ENDPOINTS) {
                debug("Processing endpoint: " + endpoint.name);
                Json::Value data = fetchEndpoint(endpoint);
                if (!data.empty()) {
                    saveJson("repsly_" + endpoint.name + "_raw.json", data, endpoint.name);
                }
            }
            debug("Finished fetchAll");
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
}

int main(int argc, char* argv[]) {
    bool no_pagination = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg == "--no-pagination") {
            no_pagination = true;
        } else if (arg == "--debug" || arg == "-d") {
            Repsly::debug_enabled = true;
            Repsly::debug_log.open("repsly2json_debug.log", std::ios::out | std::ios::app);
            if (!Repsly::debug_log.is_open()) {
                std::cerr << "Error: Could not open debug log file" << std::endl;
                return 1;
            }
        }
    }

    try {
        Repsly::debug("Starting main");
        Repsly::Client client("/etc/api/config.conf", no_pagination);
        client.fetchAll();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    Repsly::debug("Exiting main");
    return 0;
}
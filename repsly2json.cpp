/* 

I use this for compiling...

g++ -Wall -Wextra -Werror -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wformat -Werror=format-security -fPIE -pie repsly2json.cpp -o repsly2json -lcurl -ljsoncpp -march=native -mtune=native

Requires: JSON-C, LibPQxx, LibCURL
*/

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <ctime>
#include <regex>
#include <iomanip>
#include <curl/curl.h>
#include <jsoncpp/json/json.h>
#include <unistd.h>

constexpr size_t MAX_URL_LEN = 512;
constexpr size_t MAX_CONFIG_LEN = 1024;
constexpr int DEFAULT_SLEEP_MS = 300;
constexpr size_t MAX_ID_LEN = 128;
constexpr size_t MAX_DATE_LEN = 11;
constexpr char DEFAULT_START_DATE[] = "2023-01-01";
constexpr char DEFAULT_END_DATE[] = "2023-12-31";
constexpr size_t STATUS_LEN = 256;

enum class PaginationType {
   NONE,
   ID,
   TIMESTAMP,
   SKIP,
   DATE_RANGE
};

struct Endpoint {
   std::string name;
   std::string url_format;
   std::string key;
   PaginationType pagination;
};

struct Progress {
   int total{0};
   int processed{0};
   std::string status;
};

struct PaginationState {
   std::string current_date{DEFAULT_START_DATE};
   std::string end_date{DEFAULT_END_DATE};
   std::string last_id{"0"};
   int skip{0};
   Json::Value meta;
};

class RepslyClient {
private:
   CURL* curl;
   std::string username;
   std::string password;
   static const std::vector<Endpoint> ENDPOINTS;

   static size_t WriteCallback(char* data, size_t size, size_t nmemb, std::string* buffer) {
       buffer->append(data, size * nmemb);
       return size * nmemb;
   }

    void constructUrl(std::string& url, const Endpoint& endpoint, const PaginationState& state) const {
        char buffer[MAX_URL_LEN];
        switch(endpoint.pagination) {
            case PaginationType::SKIP:
                snprintf(buffer, sizeof(buffer), endpoint.url_format.c_str(), 
                        API_BASE, state.last_id.c_str(), state.skip);
                break;
            case PaginationType::DATE_RANGE:
                snprintf(buffer, sizeof(buffer), endpoint.url_format.c_str(),
                        API_BASE, state.current_date.c_str(), state.end_date.c_str());
                break;
            case PaginationType::ID:
            case PaginationType::TIMESTAMP:
                snprintf(buffer, sizeof(buffer), endpoint.url_format.c_str(),
                        API_BASE, state.last_id.c_str());
                break;
            case PaginationType::NONE:
                snprintf(buffer, sizeof(buffer), endpoint.url_format.c_str(), API_BASE);
                break;
            default:
                throw std::runtime_error("Unsupported pagination type");
        }
        url = buffer;
    }

   bool updatePagination(const Endpoint& endpoint, const Json::Value& meta, 
                        const Json::Value& items, PaginationState& state, Progress& progress) {
       int len = items.size();
       progress.processed += len;
        if (meta.isMember("MetaCollectionResult")) {
        state.meta = meta["MetaCollectionResult"];
        }
       switch(endpoint.pagination) {
           case PaginationType::TIMESTAMP: {
               if (!meta.isMember("LastTimeStamp")) return false;
               long long new_ts = meta["LastTimeStamp"].asInt64();
               long long current_ts = std::stoll(state.last_id);
               
               if (new_ts > current_ts) {
                   state.last_id = std::to_string(new_ts);
                   progress.status = "TS: " + state.last_id;
                   return len > 0;
               }
               return false;
           }

            case PaginationType::ID: {
            if (!meta.isMember("FirstID") || !meta.isMember("LastID") || !meta.isMember("TotalCount")) {
                return false;
            }

            int total_count = meta["TotalCount"].asInt();
            if (total_count == 0) {
                return false;
            }

            long long new_id = meta["LastID"].asInt64();
            if (state.last_id == "0") {
                new_id = meta["FirstID"].asInt64();
            }
            
            long long current_id = std::stoll(state.last_id);
            if (new_id > current_id) {
                state.last_id = std::to_string(new_id);
                progress.status = "ID: " + state.last_id;
                return len > 0;
            }
            return false;
            }

           case PaginationType::SKIP:
               state.skip += len;
               return len > 0;
           
           case PaginationType::DATE_RANGE: {
               std::tm tm = {};
               strptime(state.current_date.c_str(), "%Y-%m-%d", &tm);
               tm.tm_mday++;
               mktime(&tm);
               char buffer[MAX_DATE_LEN];
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
       curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
       curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
       curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
       curl_easy_setopt(curl, CURLOPT_USERNAME, username.c_str());
       curl_easy_setopt(curl, CURLOPT_PASSWORD, password.c_str());

       if (curl_easy_perform(curl) != CURLE_OK) return Json::Value();

       long http_code;
       curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
       if (http_code != 200) return Json::Value();

       Json::Value root;
       Json::Reader().parse(response, root);
       return root;
   }

    void saveJson(const std::string& filename, const Json::Value& json) {
        mkdir("json_dl", 0777);
        std::ofstream file("json_dl/" + filename);
        if (file.is_open()) {
            Json::FastWriter writer;
            file << writer.write(json);
        } else {
            std::cerr << "Failed to open file: " << filename << std::endl;
        }
    }

    void savePricelistItems(const std::string& pricelistId, const Json::Value& pricelistItemsData) {
        mkdir("json_dl", 0777); 
        std::string filename = "repsly_pricelistsItems_" + pricelistId + "_raw.json";
        std::string filepath = "json_dl/" + filename;
        std::ofstream file(filepath);
        if (file.is_open()) {
            Json::FastWriter writer;
            file << writer.write(pricelistItemsData);
            file.close(); 
            std::cout << "Saved pricelistItems for pricelistId " << pricelistId << " to " << filepath << std::endl;
        } else {
            std::cerr << "Failed to open file: " << filepath << std::endl;
        }
    }

   void reportProgress(const std::string& endpoint, const Progress& p) {
       std::cout << "\r" << std::left << std::setw(20) << endpoint;
       if (p.total > 0) std::cout << "[" << p.processed << "/" << p.total << "] ";
       if (!p.status.empty()) std::cout << p.status;
       std::cout << "    \r" << std::flush;
   }

    Json::Value fetchEndpoint(const Endpoint& endpoint, PaginationState state = PaginationState()) {
        Json::Value responses(Json::arrayValue);
        Progress progress;
        bool has_more = true;

        while (has_more) {
            std::string url;
            constructUrl(url, endpoint, state);

            if (auto page = fetchPage(url)) {
                if (!page.isMember(endpoint.key)) break; 

                if (page.isMember("MetaCollectionResult")) {
                    state.meta = page["MetaCollectionResult"];
                }

                if (endpoint.name == "pricelists") {
                    const Json::Value& pricelists = page[endpoint.key];
                    for (const auto& pricelist : pricelists) {
                        if (pricelist.isMember("pricelistId")) {
                            std::string pricelistId = pricelist["pricelistId"].asString();


                            Endpoint pricelistItemsEndpoint = {"pricelistsItems", "%s/pricelistsItems/%s", "PricelistsItems", PaginationType::NONE};
                            PaginationState pricelistItemsState;
                            pricelistItemsState.last_id = pricelistId; 

                            Json::Value pricelistItemsResponse = fetchEndpoint(pricelistItemsEndpoint, pricelistItemsState);
                            if (!pricelistItemsResponse.empty()) {

                                savePricelistItems(pricelistId, pricelistItemsResponse);
                            }
                        }
                    }
                } else {
                    responses.append(page);
                }
                auto& items = page[endpoint.key];
                auto& meta = page["MetaCollectionResult"];

                if (!progress.total && meta.isMember("TotalCount")) {
                    progress.total = meta["TotalCount"].asInt();
                }

               if (endpoint.pagination != PaginationType::NONE) {
                    has_more = updatePagination(endpoint, meta, items, state, progress);
                } else {

                }
                reportProgress(endpoint.name, progress);
                usleep(DEFAULT_SLEEP_MS * 1000);
            } else break;
        }
        std::cout << std::endl;

        Json::Value output;
        output["MetaCollectionResult"] = state.meta;
        output["Data"] = responses;
        return output;
    }

public:
   RepslyClient(const std::string& config_path) {
       auto [user, pass] = readConfig(config_path);
       username = user;
       password = pass;
       curl = curl_easy_init();
       if (!curl || username.empty() || password.empty()) {
           throw std::runtime_error("Failed to initialize client");
       }
   }

   ~RepslyClient() {
       if(curl) curl_easy_cleanup(curl);
   }

    void fetchAll() {
        for (const auto& endpoint : ENDPOINTS) {
            std::cout << "Processing " << endpoint.name << "...\n";
            if (auto data = fetchEndpoint(endpoint)) {
                if (endpoint.name == "pricelists") {

                    saveJson("repsly_pricelists_raw.json", data);
                } else {

                    saveJson("repsly_" + endpoint.name + "_raw.json", data);
                }
            }
        }
    }

   static std::pair<std::string, std::string> readConfig(const std::string& path) {
       std::ifstream file(path);
       std::string line, user, pass;
       while (std::getline(file, line)) {
           if (line[0] == '#') continue;
           std::smatch matches;
           if (std::regex_match(line, matches, std::regex(R"((\w+)=\"(.+)\")"))) {
               if (matches[1] == "REPSLY_USER") user = matches[2];
               else if (matches[1] == "REPSLY_PASS") pass = matches[2];
           }
       }
       return {user, pass};
   }
};

const std::vector<Endpoint> RepslyClient::ENDPOINTS = {

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

int main() {
   try {
       RepslyClient client("/etc/api/config.conf");
       client.fetchAll();
   } catch (const std::exception& e) {
       std::cerr << "Error: " << e.what() << std::endl;
       return 1;
   }
   return 0;
}

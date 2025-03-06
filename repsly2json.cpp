/*

Author: Benjamin Cance
Date: 03/06/2025
Email: bjc@tdx.li

Description: A data export utility for the Repsly API that retrieves and converts Repsly data to JSON format for further processing or archiving.

Compile with: g++ -Wall -Wextra -Werror -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wformat -Werror=format-security -fPIE -pie repsly2json.cpp -o repsly2json -lcurl -ljsoncpp -march=native -mtune=native

*/
    
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
#include <thread>
#include <mutex>
#include <atomic>
#include <optional>
#include <sstream>
#include <memory>
#include <set>
#include <deque>
#include <unordered_map>

namespace fs = std::filesystem;

namespace Repsly {
    constexpr size_t MAX_URL_LEN = 512;
    constexpr int DEFAULT_SLEEP_MS = 300;
    constexpr char API_BASE[] = "https://api.repsly.com/v3/export";    
    constexpr char DEFAULT_START_DATE[] = "2020-01-01";
    constexpr char DEFAULT_END_DATE[] = "2020-12-31";
    constexpr int MAX_RETRIES = 3;
    constexpr int RETRY_DELAY_MS = 1000;
    constexpr int VISIT_REALIZATIONS_MAX_SKIP = 9500;
    constexpr int VISIT_REALIZATIONS_PAGE_SIZE = 50;

    enum class PaginationType { NONE, ID, TIMESTAMP, SKIP, DATE_RANGE };

    class ApiException : public std::runtime_error {
    public:
        explicit ApiException(const std::string& message) : std::runtime_error(message) {}
    };

    class NetworkException : public ApiException {
    public:
        explicit NetworkException(const std::string& message) : ApiException(message) {}
    };

    class JsonParseException : public ApiException {
    public:
        explicit JsonParseException(const std::string& message) : ApiException(message) {}
    };

    class ConfigException : public ApiException {
    public:
        explicit ConfigException(const std::string& message) : ApiException(message) {}
    };

    class Logger {
    private:
        std::mutex log_mutex_;
        enum class LogLevel { DEBUG, INFO, WARNING, ERROR };
        LogLevel current_level_ = LogLevel::INFO;

    public:
        void setLevel(const std::string& level) {
            if (level == "DEBUG") current_level_ = LogLevel::DEBUG;
            else if (level == "INFO") current_level_ = LogLevel::INFO;
            else if (level == "WARNING") current_level_ = LogLevel::WARNING;
            else if (level == "ERROR") current_level_ = LogLevel::ERROR;
        }

        void debug(const std::string& message) {
            if (current_level_ <= LogLevel::DEBUG) {
                log(message, "DEBUG");
            }
        }

        void info(const std::string& message) {
            if (current_level_ <= LogLevel::INFO) {
                log(message, "INFO");
            }
        }

        void warning(const std::string& message) {
            if (current_level_ <= LogLevel::WARNING) {
                log(message, "WARNING");
            }
        }

        void error(const std::string& message) {
            if (current_level_ <= LogLevel::ERROR) {
                log(message, "ERROR");
            }
        }

    private:
        void log(const std::string& message, const std::string& level) {
            std::lock_guard<std::mutex> lock(log_mutex_);
            auto now = std::chrono::system_clock::now();
            auto time = std::chrono::system_clock::to_time_t(now);
            std::stringstream ss;
            ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
            
            if (level == "ERROR" || level == "WARNING") {
                std::cerr << "[" << ss.str() << "] [" << level << "] " << message << std::endl;
            } else {
                std::cout << "[" << ss.str() << "] [" << level << "] " << message << std::endl;
            }
        }
    };

    Logger& getLogger() {
        static Logger logger;
        return logger;
    }

    struct Endpoint {
        std::string name;
        std::string url_format;
        std::string key;
        PaginationType pagination;
    };

    struct Progress {
        std::atomic<int> total{0};
        std::atomic<int> processed{0};
        std::string status;
        std::mutex status_mutex;

        void setStatus(const std::string& new_status) {
            std::lock_guard<std::mutex> lock(status_mutex);
            status = new_status;
        }

        std::string getStatus() {
            std::lock_guard<std::mutex> lock(status_mutex);
            return status;
        }
    };

    struct PaginationState {
        std::string current_date = DEFAULT_START_DATE;
        std::string end_date = DEFAULT_END_DATE;
        std::string last_id = "0";
        int skip = 0;
        Json::Value meta;
    };

    class DateUtils {
    public:
        static std::string advanceDay(const std::string& date) {
            std::tm tm{};
            std::istringstream ss(date);
            ss >> std::get_time(&tm, "%Y-%m-%d");
            if (ss.fail()) {
                throw ApiException("Invalid date format: " + date);
            }
            
            tm.tm_mday++;
            std::mktime(&tm);
            
            std::ostringstream result;
            result << std::put_time(&tm, "%Y-%m-%d");
            return result.str();
        }
        
        static bool isDateBefore(const std::string& date1, const std::string& date2) {
            return date1 <= date2;
        }
        
        static std::string getCurrentDateISO8601() {
            auto now = std::chrono::system_clock::now();
            auto time = std::chrono::system_clock::to_time_t(now);
            std::stringstream ss;
            ss << std::put_time(std::gmtime(&time), "%Y-%m-%dT%H:%M:%S.000Z");
            return ss.str();
        }
        
        static std::string getCurrentDateStamp() {
            auto now = std::chrono::system_clock::now();
            auto time = std::chrono::system_clock::to_time_t(now);
            std::stringstream ss;
            ss << std::put_time(std::localtime(&time), "%Y%m%d");
            return ss.str();
        }
        
        static std::string formatISO8601Date(const std::string& date) {
            if (date.length() >= 10) {
                return date.substr(0, 10) + "T00:00:00.000Z";
            }
            return date + "T00:00:00.000Z";
        }
    };

    class ConfigManager {
    public:
        static std::pair<std::string, std::string> readConfig(const std::string& path) {
            std::ifstream file(path);
            if (!file) {
                throw ConfigException("Cannot open config file: " + path);
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
            
            if (user.empty() || pass.empty()) {
                throw ConfigException("Missing credentials in " + path);
            }
            
            return {user, pass};
        }
    };

    class RateLimiter {
    private:
        std::chrono::milliseconds base_delay_{DEFAULT_SLEEP_MS};
        std::chrono::milliseconds current_delay_{DEFAULT_SLEEP_MS};
        std::chrono::milliseconds max_delay_{5000};         std::chrono::milliseconds min_delay_{100};          std::deque<std::chrono::milliseconds> response_times_;
        size_t max_samples_{10};
        std::mutex limiter_mutex_;
        
    public:
        void recordResponseTime(std::chrono::milliseconds time) {
            std::lock_guard<std::mutex> lock(limiter_mutex_);
            response_times_.push_back(time);
            if (response_times_.size() > max_samples_) {
                response_times_.pop_front();
            }
            adjustDelay();
        }
        
        void recordFailure() {
            std::lock_guard<std::mutex> lock(limiter_mutex_);
            current_delay_ = std::min(current_delay_ * 2, max_delay_);
        }
        
        void wait() {
            std::this_thread::sleep_for(getDelay());
        }
        
        std::chrono::milliseconds getDelay() {
            std::lock_guard<std::mutex> lock(limiter_mutex_);
            return current_delay_;
        }
        
    private:
        void adjustDelay() {
            if (response_times_.empty()) return;
            
            std::chrono::milliseconds total{0};
            for (const auto& time : response_times_) {
                total += time;
            }
            auto avg = total / response_times_.size();
            
                        if (avg.count() > 500) {
                current_delay_ = std::min(current_delay_ * 3 / 2, max_delay_);
            } else if (avg.count() < 200) {
                current_delay_ = std::max(current_delay_ * 2 / 3, min_delay_);
            }
        }
    };

    class ApiClient {
    private:
        std::mutex curl_mutex_;
        CURL* curl_ = nullptr;
        std::string username_;
        std::string password_;
        std::unique_ptr<RateLimiter> rate_limiter_;
        
        static size_t WriteCallback(char* data, size_t size, size_t nmemb, std::string* buffer) {
            buffer->append(data, size * nmemb);
            return size * nmemb;
        }
        
    public:
        ApiClient(const std::string& username, const std::string& password) 
            : username_(username), password_(password), rate_limiter_(std::make_unique<RateLimiter>()) {
            curl_ = curl_easy_init();
            if (!curl_) {
                throw NetworkException("Failed to initialize CURL");
            }
        }
        
        ~ApiClient() {
            if (curl_) {
                std::lock_guard<std::mutex> lock(curl_mutex_);
                curl_easy_cleanup(curl_);
                curl_ = nullptr;
            }
        }
        
        ApiClient(const ApiClient&) = delete;
        ApiClient& operator=(const ApiClient&) = delete;
        
        Json::Value fetchUrl(const std::string& url, int retryCount = 0) {
            std::lock_guard<std::mutex> lock(curl_mutex_);
            std::string response;
            
            auto start_time = std::chrono::steady_clock::now();
            
            curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &response);
            curl_easy_setopt(curl_, CURLOPT_USERNAME, username_.c_str());
            curl_easy_setopt(curl_, CURLOPT_PASSWORD, password_.c_str());
            curl_easy_setopt(curl_, CURLOPT_TIMEOUT, 30L);
            curl_easy_setopt(curl_, CURLOPT_CONNECTTIMEOUT, 10L);

            CURLcode res = curl_easy_perform(curl_);
            
            auto end_time = std::chrono::steady_clock::now();
            auto response_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                end_time - start_time);
            
            if (res != CURLE_OK) {
                rate_limiter_->recordFailure();
                if (retryCount < MAX_RETRIES) {
                    getLogger().warning("CURL error: " + std::string(curl_easy_strerror(res)) + 
                                      " for " + url + ". Retrying...");
                    std::this_thread::sleep_for(std::chrono::milliseconds(RETRY_DELAY_MS));
                    return fetchUrl(url, retryCount + 1);
                }
                throw NetworkException("CURL error: " + std::string(curl_easy_strerror(res)) + 
                                     " for " + url + " after " + std::to_string(MAX_RETRIES) + " retries");
            }

            long http_code = 0;
            curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &http_code);
            if (http_code != 200) {
                rate_limiter_->recordFailure();
                if (retryCount < MAX_RETRIES && (http_code == 429 || http_code >= 500)) {
                    getLogger().warning("HTTP error " + std::to_string(http_code) + 
                                      " for " + url + ". Retrying...");
                    std::this_thread::sleep_for(std::chrono::milliseconds(RETRY_DELAY_MS * (retryCount + 1)));
                    return fetchUrl(url, retryCount + 1);
                }
                throw NetworkException("HTTP error " + std::to_string(http_code) + " for " + url);
            }

            Json::Value root;
            Json::Reader reader;
            if (!reader.parse(response, root)) {
                throw JsonParseException("JSON parse error for " + url);
            }
            
                        rate_limiter_->recordResponseTime(response_time);
            
            return root;
        }
        
        void waitForRateLimit() {
            rate_limiter_->wait();
        }
        
        std::string pingServer() {
            try {
                                std::string ping_url = std::string(API_BASE) + "/representatives";
                
                auto start_time = std::chrono::steady_clock::now();
                
                                std::lock_guard<std::mutex> lock(curl_mutex_);
                curl_easy_setopt(curl_, CURLOPT_URL, ping_url.c_str());
                curl_easy_setopt(curl_, CURLOPT_NOBODY, 1L);                 curl_easy_setopt(curl_, CURLOPT_USERNAME, username_.c_str());
                curl_easy_setopt(curl_, CURLOPT_PASSWORD, password_.c_str());
                curl_easy_setopt(curl_, CURLOPT_TIMEOUT, 10L);
                curl_easy_setopt(curl_, CURLOPT_CONNECTTIMEOUT, 5L);
                
                CURLcode res = curl_easy_perform(curl_);
                
                                curl_easy_setopt(curl_, CURLOPT_NOBODY, 0L);
                
                auto end_time = std::chrono::steady_clock::now();
                auto ping_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                    end_time - start_time);
                    
                if (res != CURLE_OK) {
                    return "Server ping failed: " + std::string(curl_easy_strerror(res));
                }
                
                long http_code = 0;
                curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &http_code);
                
                if (http_code >= 200 && http_code < 300) {
                    return "Server ping: " + std::to_string(ping_time.count()) + "ms";
                } else {
                    return "Server ping error: HTTP " + std::to_string(http_code) + 
                           " (" + std::to_string(ping_time.count()) + "ms)";
                }
            } catch (const std::exception& e) {
                return "Server ping failed: " + std::string(e.what());
            }
        }
    };

    class JsonStorage {
    private:
        std::string output_dir_;
        std::mutex io_mutex_;
        
    public:
        explicit JsonStorage(const std::string& output_dir = "json_dl") 
            : output_dir_(output_dir) {
            try {
                fs::create_directory(output_dir_);
            } catch (const fs::filesystem_error& e) {
                throw ApiException("Failed to create directory: " + output_dir_ + ": " + e.what());
            }
        }
        
        void saveJson(const std::string& filename, const Json::Value& json) {
            std::lock_guard<std::mutex> lock(io_mutex_);
            std::ofstream file(output_dir_ + "/" + filename);
            if (!file) {
                throw ApiException("Failed to open file: " + output_dir_ + "/" + filename);
            }
            
            Json::StreamWriterBuilder builder;
            builder["indentation"] = "";
            std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
            writer->write(json, &file);
        }
        
        Json::Value loadJson(const std::string& filename) {
            std::lock_guard<std::mutex> lock(io_mutex_);
            std::ifstream file(output_dir_ + "/" + filename);
            Json::Value root;
            
            if (file) {
                Json::Reader reader;
                if (!reader.parse(file, root)) {
                    getLogger().warning("Failed to parse JSON file: " + filename);
                }
            }
            
            return root;
        }
        
        bool fileExists(const std::string& filename) {
            return fs::exists(output_dir_ + "/" + filename);
        }
    };

    class ProgressReporter {
    private:
        std::string endpoint_name_;
        Progress& progress_;
        std::mutex display_mutex_;
        
    public:
        ProgressReporter(const std::string& endpoint_name, Progress& progress) 
            : endpoint_name_(endpoint_name), progress_(progress) {}
        
        void update(int processed, int total = 0, const std::string& status = "") {
            progress_.processed = processed;
            if (total > 0) progress_.total = total;
            if (!status.empty()) progress_.setStatus(status);
            report();
        }
        
        int getCurrentProcessed() const {
            return progress_.processed;
        }

        void report() {
            std::lock_guard<std::mutex> lock(display_mutex_);
            std::cout << "\r" << std::left << std::setw(20) << endpoint_name_;
            if (progress_.total > 0) {
                std::cout << "[" << progress_.processed << "/" << progress_.total << "] ";
            }
            std::string status = progress_.getStatus();
            if (!status.empty()) std::cout << status;
            std::cout << std::flush;
        }
        
        void complete() {
            report();
            std::cout << std::endl;
        }
    };

    class PaginationManager {
    private:
        bool no_pagination_;
        
    public:
        explicit PaginationManager(bool no_pagination = false)
            : no_pagination_(no_pagination) {}
        
        std::string constructUrl(const Endpoint& endpoint, const PaginationState& state) const {
            char buffer[MAX_URL_LEN];
            int written = 0;
            
            if (endpoint.pagination == PaginationType::NONE && 
                endpoint.name == "pricelistsItems" && 
                (state.last_id.empty() || state.last_id == "0")) {
                throw ApiException("pricelistsItems requires a valid pricelistId");
            }
            
            switch (endpoint.pagination) {
                case PaginationType::SKIP:
                    written = snprintf(buffer, MAX_URL_LEN, endpoint.url_format.c_str(), 
                                     API_BASE, state.last_id.c_str(), state.skip);
                    break;
                case PaginationType::DATE_RANGE:
                    written = snprintf(buffer, MAX_URL_LEN, endpoint.url_format.c_str(), 
                                     API_BASE, state.current_date.c_str(), state.end_date.c_str());
                    break;
                case PaginationType::ID:
                case PaginationType::TIMESTAMP:
                    written = snprintf(buffer, MAX_URL_LEN, endpoint.url_format.c_str(), 
                                     API_BASE, state.last_id.c_str());
                    break;
                case PaginationType::NONE:
                    written = snprintf(buffer, MAX_URL_LEN, endpoint.url_format.c_str(), API_BASE);
                    break;
                default:
                    throw ApiException("Unsupported pagination type");
            }
            
            if (written < 0 || static_cast<size_t>(written) >= MAX_URL_LEN) {
                throw ApiException("URL construction failed: buffer overflow");
            }
            
            return std::string(buffer);
        }
        
        bool shouldPaginate(const Endpoint& endpoint) const {
            return !no_pagination_ && endpoint.pagination != PaginationType::NONE;
        }
        
        bool updatePagination(const Endpoint& endpoint, const Json::Value& meta, 
                            const Json::Value& items, PaginationState& state, 
                                    ProgressReporter& reporter) {
            int newProcessed = reporter.getCurrentProcessed() + items.size();
            reporter.update(newProcessed);
            
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
                    reporter.update(newProcessed, 0, "TS: " + state.last_id);
                    return items.size() > 0;
                }
                case PaginationType::ID: {
                    if (!meta.isMember("FirstID") || !meta.isMember("LastID") || 
                        !meta.isMember("TotalCount")) return false;
                    int total_count = meta["TotalCount"].asInt();
                    if (total_count == 0) return false;
                    int64_t new_id = (state.last_id == "0") ? 
                                    meta["FirstID"].asInt64() : meta["LastID"].asInt64();
                    int64_t current_id = std::stoll(state.last_id);
                    if (new_id <= current_id) return false;
                    state.last_id = std::to_string(new_id);
                    reporter.update(newProcessed, 0, "ID: " + state.last_id);
                    return items.size() > 0;
                }
                case PaginationType::SKIP:
                    state.skip += items.size();
                    return items.size() > 0;
                case PaginationType::DATE_RANGE: {
                    try {
                        std::string next_date = DateUtils::advanceDay(state.current_date);
                        state.current_date = next_date;
                        reporter.update(newProcessed, 0, "Date: " + state.current_date);
                        return DateUtils::isDateBefore(state.current_date, state.end_date);
                    } catch (const ApiException& e) {
                        getLogger().error("Date error: " + std::string(e.what()));
                        return false;
                    }
                }
                default:
                    return false;
            }
        }
    };

    class VisitRealizationsManager {
    private:
        ApiClient* api_client_;
        JsonStorage* storage_;
        std::string initial_date_ = "2020-01-01T00:00:00.000Z";
        std::string current_date_;
        int current_skip_ = 0;
        std::string last_processed_date_;
        std::string progress_file_ = "visitrealizations_progress.json";
        int consecutive_error_count_ = 0;
        
    public:
        VisitRealizationsManager(ApiClient* api_client, JsonStorage* storage) 
            : api_client_(api_client), storage_(storage) {
            loadProgress();
        }
        
        Json::Value fetchAllVisitRealizations() {
            Json::Value allData(Json::arrayValue);
            bool hasMoreData = true;
            Progress progress;
            ProgressReporter reporter("visitrealizations", progress);
            int total_processed = 0;
            
            getLogger().info("Starting visit realizations fetch from " + current_date_);
            
            while (hasMoreData) {
                std::string url = constructUrl();
                getLogger().debug("Fetching visit realizations: " + url);
                
                Json::Value response;
                try {
                    response = api_client_->fetchUrl(url);
                    
                    if (response.isMember("VisitRealizations") && 
                        response["VisitRealizations"].isArray()) {
                        
                        const auto& items = response["VisitRealizations"];
                        int itemCount = items.size();
                        total_processed += itemCount;
                        
                        if (itemCount > 0) {
                            allData.append(response);
                            
                            std::string filename = "repsly_visitrealizations_" + 
                                                  current_date_.substr(0, 10) + "_" + 
                                                  std::to_string(current_skip_) + "_raw.json";
                            storage_->saveJson(filename, response);
                            
                            updateLastModifiedDate(items);
                            consecutive_error_count_ = 0;
                        }
                        
                        reporter.update(total_processed, 0, 
                            "Date: " + current_date_.substr(0, 10) + 
                            ", Skip: " + std::to_string(current_skip_));
                        
                        if (itemCount < VISIT_REALIZATIONS_PAGE_SIZE) {
                            current_skip_ = 0;
                            advanceDate();
                            
                            std::string today = DateUtils::getCurrentDateISO8601();
                            if (current_date_ >= today) {
                                hasMoreData = false;
                            }
                        } else {
                            current_skip_ += VISIT_REALIZATIONS_PAGE_SIZE;
                            
                            if (current_skip_ >= VISIT_REALIZATIONS_MAX_SKIP) {
                                current_skip_ = 0;
                                advanceDate();
                            }
                        }
                        
                        saveProgress();
                        
                        getLogger().info("Processed " + std::to_string(itemCount) + 
                                       " visit realizations, date: " + current_date_ + 
                                       ", skip: " + std::to_string(current_skip_));
                    } else {
                        getLogger().warning("Invalid response format from visit realizations endpoint");
                        hasMoreData = false;
                    }
                } catch (const ApiException& e) {
                    getLogger().error("Error fetching visit realizations: " + std::string(e.what()));
                    current_skip_ = 0;
                    advanceDate();
                    
                    if (consecutive_error_count_++ > 5) {
                        getLogger().error("Too many consecutive errors, stopping visit realizations fetch");
                        hasMoreData = false;
                    }
                    
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                }
                
                api_client_->waitForRateLimit();
            }
            
            reporter.complete();
            
            Json::Value output;
            output["VisitRealizations"] = allData;
            return output;
        }
        
        Json::Value fetchIncrementalVisitRealizations() {
            current_date_ = last_processed_date_;
            if (current_date_.empty()) {
                current_date_ = initial_date_;
            }
            current_skip_ = 0;
            
            return fetchAllVisitRealizations();
        }
        
    private:
        std::string constructUrl() {
            char buffer[MAX_URL_LEN];
            snprintf(buffer, MAX_URL_LEN, "%s/visitrealizations?modified=%s&skip=%d", 
                    API_BASE, current_date_.c_str(), current_skip_);
            return std::string(buffer);
        }
        
        void advanceDate() {
            std::tm tm{};
            std::istringstream ss(current_date_.substr(0, 10));
            ss >> std::get_time(&tm, "%Y-%m-%d");
            
            tm.tm_mday++;
            std::mktime(&tm);
            
            std::ostringstream result;
            result << std::put_time(&tm, "%Y-%m-%d") << "T00:00:00.000Z";
            current_date_ = result.str();
        }
        
        void updateLastModifiedDate(const Json::Value& items) {
            std::string latestDate;
            
            for (const auto& item : items) {
                if (item.isMember("ModifiedUTC")) {
                    std::string itemDate = item["ModifiedUTC"].asString();
                    if (itemDate > latestDate) {
                        latestDate = itemDate;
                    }
                }
            }
            
            if (!latestDate.empty()) {
                last_processed_date_ = latestDate;
            }
        }
        
        void saveProgress() {
            Json::Value progress;
            progress["current_date"] = current_date_;
            progress["current_skip"] = current_skip_;
            progress["last_processed_date"] = last_processed_date_;
            
            try {
                storage_->saveJson(progress_file_, progress);
            } catch (const std::exception& e) {
                getLogger().warning("Failed to save visit realizations progress: " + 
                                   std::string(e.what()));
            }
        }
        
        void loadProgress() {
            try {
                if (storage_->fileExists(progress_file_)) {
                    Json::Value progress = storage_->loadJson(progress_file_);
                    
                    if (progress.isMember("current_date")) {
                        current_date_ = progress["current_date"].asString();
                    } else {
                        current_date_ = initial_date_;
                    }
                    
                    if (progress.isMember("current_skip")) {
                        current_skip_ = progress["current_skip"].asInt();
                    }
                    
                    if (progress.isMember("last_processed_date")) {
                        last_processed_date_ = progress["last_processed_date"].asString();
                    }
                    
                    getLogger().info("Loaded visit realizations progress: date=" + 
                                   current_date_ + ", skip=" + std::to_string(current_skip_));
                } else {
                    current_date_ = initial_date_;
                }
            } catch (const std::exception& e) {
                getLogger().warning("Failed to load visit realizations progress: " + 
                                   std::string(e.what()));
                current_date_ = initial_date_;
            }
        }
    };
    
    class EndpointHandler {
    private:
        ApiClient* api_client_;
        JsonStorage* storage_;
        PaginationManager* pagination_manager_;
        
    public:
        EndpointHandler() 
            : api_client_(nullptr), storage_(nullptr), pagination_manager_(nullptr) {}
            
        EndpointHandler(ApiClient* api_client, JsonStorage* storage, 
                      PaginationManager* pagination_manager)
            : api_client_(api_client), storage_(storage), 
              pagination_manager_(pagination_manager) {}
        
        Json::Value fetchEndpoint(const Endpoint& endpoint, PaginationState state = {}) {
            Json::Value responses(Json::arrayValue);
            Progress progress;
            ProgressReporter reporter(endpoint.name, progress);
            
            getLogger().info("Fetching endpoint: " + endpoint.name);
            
            try {
                std::string url = pagination_manager_->constructUrl(endpoint, state);
                getLogger().debug("Initial URL: " + url);
                Json::Value page = api_client_->fetchUrl(url);
                if (!page.isMember(endpoint.key)) {
                    throw ApiException("Endpoint returned no data: " + endpoint.name);
                }
                
                if (page.isMember("MetaCollectionResult")) {
                    state.meta = page["MetaCollectionResult"];
                }
                
                if (endpoint.name == "pricelists") {
                    handlePricelists(page, endpoint);
                } else {
                    responses.append(page);
                }
                
                reporter.update(page[endpoint.key].size());
                const auto& meta = page["MetaCollectionResult"];
                if (meta.isMember("TotalCount")) {
                    reporter.update(page[endpoint.key].size(), meta["TotalCount"].asInt());
                }
                
                
                if (pagination_manager_->shouldPaginate(endpoint)) {
                    int total_processed = page[endpoint.key].size();
                    bool has_more = true;
                    int consecutive_errors = 0;
                    std::set<std::string> bad_ids;                     
                    while (has_more && consecutive_errors < 3) {
                        try {
                            url = pagination_manager_->constructUrl(endpoint, state);
                            getLogger().debug("Pagination URL: " + url);
                            
                            page = api_client_->fetchUrl(url);
                            if (!page.isMember(endpoint.key)) {
                                getLogger().warning("No items found in response for " + endpoint.name + ", may have reached end of data");
                                break;
                            }
                            
                            if (page.isMember("MetaCollectionResult")) {
                                state.meta = page["MetaCollectionResult"];
                            }
                            
                            responses.append(page);
                            
                            const auto& items = page[endpoint.key];
                            total_processed += items.size();
                            
                            const auto& meta_loop = page["MetaCollectionResult"];
                            has_more = pagination_manager_->updatePagination(
                                endpoint, meta_loop, items, state, reporter);
                            
                            reporter.update(total_processed);
                            consecutive_errors = 0;                             
                            api_client_->waitForRateLimit();
                            
                        } catch (const NetworkException& e) {
                            if (std::string(e.what()).find("HTTP error 400") != std::string::npos) {
                                getLogger().warning("Skipping invalid ID: " + state.last_id + " for " + endpoint.name);
                                bad_ids.insert(state.last_id);
                                
                                                                if (endpoint.pagination == PaginationType::ID) {
                                                                        int64_t next_id = std::stoll(state.last_id) + 1;
                                    state.last_id = std::to_string(next_id);
                                    has_more = true;
                                    consecutive_errors++;                                 } else {
                                    consecutive_errors++;
                                }
                            } else {
                                consecutive_errors++;
                                getLogger().error("Network error during pagination: " + std::string(e.what()));
                                std::this_thread::sleep_for(std::chrono::seconds(2));                             }
                        } catch (const JsonParseException& e) {
                            getLogger().warning("JSON parse error at ID: " + state.last_id + " for " + endpoint.name + 
                                            ", may have reached end of data");
                            
                                                        if (endpoint.pagination == PaginationType::ID) {
                                int64_t next_id = std::stoll(state.last_id) + 1;
                                state.last_id = std::to_string(next_id);
                                has_more = true;
                                consecutive_errors++;                             } else {
                                has_more = false;                             }
                        } catch (const ApiException& e) {
                            consecutive_errors++;
                            getLogger().error("API error during pagination: " + std::string(e.what()));
                            std::this_thread::sleep_for(std::chrono::seconds(2));
                        }
                        
                                                if (consecutive_errors >= 3) {
                            getLogger().warning("Too many consecutive errors for " + endpoint.name + 
                                            ", moving to next endpoint");
                        }
                    }
                    
                                        if (!bad_ids.empty()) {
                        Json::Value bad_id_list(Json::arrayValue);
                        for (const auto& id : bad_ids) {
                            bad_id_list.append(id);
                        }
                        storage_->saveJson("bad_ids_" + endpoint.name + ".json", bad_id_list);
                    }
                }
                
                reporter.complete();
                
                Json::Value output;
                output["MetaCollectionResult"] = state.meta;
                output["Data"] = responses;
                return output;
                
            } catch (const ApiException& e) {
                getLogger().error("Error processing endpoint " + endpoint.name + ": " + e.what());
                reporter.complete();
                return Json::Value();
            }
        }
        
    private:
        void handlePricelists(const Json::Value& page, const Endpoint& endpoint) {
            getLogger().info("Processing " + std::to_string(page[endpoint.key].size()) + " pricelists");
            
            for (const auto& pricelist : page[endpoint.key]) {
                if (pricelist.isMember("pricelistId")) {
                    std::string pricelistId = pricelist["pricelistId"].asString();
                    getLogger().debug("Processing pricelist items for ID: " + pricelistId);
                    
                    Endpoint items_endpoint{
                        "pricelistsItems", 
                        "%s/pricelistsItems/%s", 
                        "PricelistsItems", 
                        PaginationType::NONE
                    };
                    
                    PaginationState items_state;
                    items_state.current_date = DEFAULT_START_DATE;
                    items_state.end_date = DEFAULT_END_DATE;
                    items_state.last_id = pricelistId;
                    items_state.skip = 0;
                    items_state.meta = Json::Value();
                    
                    Json::Value items = fetchEndpoint(items_endpoint, items_state);
                    if (!items.empty()) {
                        storage_->saveJson("repsly_pricelistsItems_" + pricelistId + "_raw.json", items);
                    }
                }
            }
        }
    };
    
    class Client {
    private:
        std::unique_ptr<ApiClient> api_client_;
        std::unique_ptr<JsonStorage> storage_;
        std::unique_ptr<PaginationManager> pagination_manager_;
        std::unique_ptr<VisitRealizationsManager> visit_realizations_manager_;
        EndpointHandler endpoint_handler_;
        static const std::vector<Endpoint> ENDPOINTS;
        bool incremental_mode_;
        
    public:
        explicit Client(const std::string& config_path, bool no_pagination = false, 
                        bool incremental_mode = false) 
        : incremental_mode_(incremental_mode) {
            auto credentials = ConfigManager::readConfig(config_path);
            api_client_ = std::make_unique<ApiClient>(credentials.first, credentials.second);
            storage_ = std::make_unique<JsonStorage>("json_dl");
            pagination_manager_ = std::make_unique<PaginationManager>(no_pagination);
            visit_realizations_manager_ = std::make_unique<VisitRealizationsManager>(
                api_client_.get(), storage_.get());
            endpoint_handler_ = EndpointHandler(api_client_.get(), storage_.get(), 
                                               pagination_manager_.get());
            
            getLogger().info("Client initialized with pagination " + 
                           std::string(no_pagination ? "disabled" : "enabled") + 
                           " and mode " + 
                           std::string(incremental_mode ? "incremental" : "full"));
                           
            std::string ping_result = api_client_->pingServer();
            getLogger().info(ping_result);
        }
        
        void fetch() {
            if (incremental_mode_) {
                fetchIncremental();
            } else {
                fetchAll();
            }
        }
        
    private:
        void fetchAll() {
            getLogger().info("Starting data fetch for all endpoints");
            
                        getLogger().info("Processing endpoint: visitrealizations");
            Json::Value visit_data = visit_realizations_manager_->fetchAllVisitRealizations();
            if (!visit_data.empty()) {
                storage_->saveJson("repsly_visitrealizations_combined_raw.json", visit_data);
                getLogger().info("Saved combined data for: visitrealizations");
            }
            
                        for (const auto& endpoint : ENDPOINTS) {
                if (endpoint.name == "pricelistsItems" || endpoint.name == "visitrealizations") {
                    getLogger().debug("Skipping " + endpoint.name + " - handled separately");
                    continue;
                }
                
                getLogger().info("Processing endpoint: " + endpoint.name);
                Json::Value data = endpoint_handler_.fetchEndpoint(endpoint);
                if (!data.empty()) {
                    storage_->saveJson("repsly_" + endpoint.name + "_raw.json", data);
                    getLogger().info("Saved data for: " + endpoint.name);
                } else {
                    getLogger().warning("No data returned for: " + endpoint.name);
                }
            }
            
            getLogger().info("Data fetch completed for all endpoints");
        }
        
        void fetchIncremental() {
            getLogger().info("Starting incremental data fetch");
            
                        Json::Value visit_data = visit_realizations_manager_->fetchIncrementalVisitRealizations();
            if (!visit_data.empty()) {
                std::string date_stamp = DateUtils::getCurrentDateStamp();
                storage_->saveJson("repsly_visitrealizations_incremental_" + 
                                  date_stamp + "_raw.json", visit_data);
                getLogger().info("Saved incremental data for: visitrealizations");
            } else {
                getLogger().info("No new visit realizations data to fetch");
            }
        }
    };
    
    const std::vector<Endpoint> Client::ENDPOINTS = {
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
    
} 
class CommandLineParser {
private:
    std::unordered_map<std::string, std::string> options_;

public:
    CommandLineParser(int argc, char* argv[]) {
        for (int i = 1; i < argc; i++) {
            std::string arg = argv[i];
            
            if (arg.substr(0, 2) == "--") {
                size_t equals_pos = arg.find('=');
                if (equals_pos != std::string::npos) {
                    std::string key = arg.substr(2, equals_pos - 2);
                    std::string value = arg.substr(equals_pos + 1);
                    options_[key] = value;
                } else {
                    options_[arg.substr(2)] = "true";
                }
            }
        }
    }
    
    bool hasOption(const std::string& option) const {
        return options_.find(option) != options_.end();
    }
    
    std::string getOption(const std::string& option, const std::string& defaultValue = "") const {
        auto it = options_.find(option);
        return (it != options_.end()) ? it->second : defaultValue;
    }
};

int main(int argc, char* argv[]) {
    curl_global_init(CURL_GLOBAL_ALL);
    
    CommandLineParser parser(argc, argv);
    bool no_pagination = parser.hasOption("no-pagination");
    bool incremental_mode = parser.hasOption("incremental");
    std::string config_path = parser.getOption("config", "/etc/api/config.conf");
    std::string log_level = parser.getOption("log-level", "INFO");
    
    Repsly::getLogger().setLevel(log_level);
    
    try {
        Repsly::getLogger().info("Starting Repsly to JSON export");
        Repsly::Client client(config_path, no_pagination, incremental_mode);
        client.fetch();
        Repsly::getLogger().info("Export completed successfully");
    } catch (const Repsly::ApiException& e) {
        Repsly::getLogger().error("API Error: " + std::string(e.what()));
        return 1;
    } catch (const std::exception& e) {
        Repsly::getLogger().error("Unexpected error: " + std::string(e.what()));
        return 1;
    }
    
    curl_global_cleanup();
    return 0;
}

/*******************************************************************************
 * Copyright (c) 2020 Red Hat Inc
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
#include "hawkbit.h"
#include <iomanip>
#include <sstream>
#include <json.hpp>
using json = nlohmann::json;

static const char* TAG = "hawkbit";

esp_err_t _http_event_handler(esp_http_client_event_t *evt)
{
    static char *output_buffer;  // Buffer to store response of http request from event handler
    static int output_len;       // Stores number of bytes read
    switch(evt->event_id) {
        case HTTP_EVENT_ERROR:
            ESP_LOGD(TAG, "HTTP_EVENT_ERROR");
            break;
        case HTTP_EVENT_ON_CONNECTED:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_CONNECTED");
            break;
        case HTTP_EVENT_HEADER_SENT:
            ESP_LOGD(TAG, "HTTP_EVENT_HEADER_SENT");
            break;
        case HTTP_EVENT_ON_HEADER:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
            break;
        case HTTP_EVENT_REDIRECT:
            ESP_LOGD(TAG, "HTTP_EVENT_REDIRECT");
            break;
        case HTTP_EVENT_ON_DATA:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
            /*
             *  Check for chunked encoding is added as the URL for chunked encoding used in this example returns binary data.
             *  However, event handler can also be used in case chunked encoding is used.
             */
            if (!esp_http_client_is_chunked_response(evt->client)) {
                // If user_data buffer is configured, copy the response into the buffer
                if (evt->user_data) {
                    memcpy((uint8_t*)evt->user_data + output_len, evt->data, evt->data_len);
                } else {
                    if (output_buffer == NULL) {
                        output_buffer = (char *) malloc(esp_http_client_get_content_length(evt->client));
                        output_len = 0;
                        if (output_buffer == NULL) {
                            ESP_LOGE(TAG, "Failed to allocate memory for output buffer");
                            return ESP_FAIL;
                        }
                    }
                    memcpy(output_buffer + output_len, evt->data, evt->data_len);
                }
                output_len += evt->data_len;
            }

            break;
        case HTTP_EVENT_ON_FINISH:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_FINISH");
            if (output_buffer != NULL) {
                // Response is accumulated in output_buffer. Uncomment the below line to print the accumulated response
                // ESP_LOG_BUFFER_HEX(TAG, output_buffer, output_len);
                free(output_buffer);
                output_buffer = NULL;
            }
            output_len = 0;
            break;
        case HTTP_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "HTTP_EVENT_DISCONNECTED");
            int mbedtls_err = 0;
            esp_err_t err = esp_tls_get_and_clear_last_error((esp_tls_error_handle_t)evt->data, &mbedtls_err, NULL);
            if (err != 0) {
                if (output_buffer != NULL) {
                    free(output_buffer);
                    output_buffer = NULL;
                }
                output_len = 0;
                ESP_LOGI(TAG, "Last esp error code: 0x%x", err);
                ESP_LOGI(TAG, "Last mbedtls failure: 0x%x", mbedtls_err);
            }
            break;
    }
    return ESP_OK;
}

void HawkbitClient::init(
    const std::string& baseUrl,
    const std::string& tenantName,
    const std::string& controllerId,
    const std::string &securityToken,
    char *server_cert_pem_start)
{
    _baseUrl = baseUrl;
    _tenantName = tenantName;
    _controllerId = controllerId;
    _authToken = "TargetToken " + securityToken;
    _doc = json::object();
    _http_config.event_handler = _http_event_handler;
    _http_config.url = "http://localhost";
    _http_config.user_data = resultPayload;        // Pass address of local buffer to get response
    _http_config.disable_auto_redirect = false;
    _http_config.cert_pem = server_cert_pem_start;
}

esp_http_client_handle_t HawkbitClient::initHttpHandle(esp_http_client_method_t method, const std::string &url) {
    esp_http_client_handle_t _http = esp_http_client_init(&_http_config);
    esp_http_client_set_url(_http, url.c_str());
    esp_http_client_set_method(_http, method);
    esp_http_client_set_header(_http, "Accept", "application/hal+json");
    esp_http_client_set_header(_http, "Content-Type", "application/json");
    esp_http_client_set_header(_http, "Authorization", this->_authToken.c_str());

    return _http;
}

UpdateResult HawkbitClient::updateRegistration(const Registration& registration, const std::map<std::string,std::string>& data, MergeMode mergeMode, std::initializer_list<std::string> details)
{
    _doc = json::object();

    switch(mergeMode) {
        case MERGE:
            _doc["mode"] = "merge";
            break;
        case REPLACE:
            _doc["mode"] = "replace";
            break;
        case REMOVE:
            _doc["mode"] = "remove";
            break;
    }

    for (const std::pair<std::string,std::string> entry : data) {
        _doc["data"][std::string(entry.first)] = entry.second;
    }

    _doc["status"]["details"] = details;

    _doc["status"]["execution"] = "closed";
    _doc["status"]["result"]["finished"] = "success";
    esp_http_client_handle_t _http = initHttpHandle(HTTP_METHOD_PUT, registration.url());

    std::string buffer = _doc.dump();
    size_t len = buffer.length();
    (void)len; // ignore unused

    ESP_LOGI(TAG,"JSON - len: %d", len);
    esp_http_client_set_post_field(_http, buffer.data(), len);
    esp_err_t err = esp_http_client_perform(_http);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "updateRegistration HTTP Status = %d, content_length = %lld",
                esp_http_client_get_status_code(_http),
                esp_http_client_get_content_length(_http));

        ESP_LOGI(TAG,"Result - payload: %s", this->resultPayload);
    } else {
        ESP_LOGE(TAG, "updateRegistration HTTP request failed: %s", esp_err_to_name(err));
    }
    int code = esp_http_client_get_status_code(_http);
    ESP_LOGD(TAG,"Result - code: %d", code);

    esp_http_client_cleanup(_http);

    return UpdateResult(code);
}

State HawkbitClient::readState()
{
    esp_http_client_handle_t _http = initHttpHandle(HTTP_METHOD_GET, (this->_baseUrl + "/" + this->_tenantName + "/controller/v1/" + this->_controllerId));

    _doc = json::object();

    esp_err_t err = esp_http_client_perform(_http);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "readState HTTP Status = %d, content_length = %lld",
                esp_http_client_get_status_code(_http),
                esp_http_client_get_content_length(_http));

            int code = esp_http_client_get_status_code(_http);
            ESP_LOGD(TAG,"Result - code: %d", code);

            ESP_LOGD(TAG,"Result - payload: %s", this->resultPayload);
            if ( code == HttpStatus_Ok ) {
                _doc = json::parse(resultPayload, NULL, false, true);
                if (_doc.is_null())
                {                    
                    ESP_LOGE(TAG, "readState: DeserializationError");
                    esp_http_client_cleanup(_http);
                    return State();
                }
            } else {
                    ESP_LOGE(TAG, "readState: not succesful with %d", esp_http_client_get_status_code(_http));
                    esp_http_client_cleanup(_http);
                    return State();
            }
            esp_http_client_cleanup(_http);

            if (_doc.count("config") && _doc["config"].count("polling") && _doc["config"]["polling"].count("sleep"))
            {
                std::string tmp = _doc["config"]["polling"]["sleep"].get<std::string>();
                if (!tmp.empty()) {
                    struct std::tm tm;
                    std::istringstream ss(tmp);
                    ss >> std::get_time(&tm, "%H:%M:%S");
                    this->pollingTime = tm.tm_hour*60*60 + tm.tm_min*60 + tm.tm_sec;
                    ESP_LOGI(TAG, "Received polling time: %s --> sleep %" PRIu32 " seconds", tmp.c_str(), this->pollingTime);
                }
            }

            if (_doc.count("_links") && _doc["_links"].count("deploymentBase") && _doc["_links"]["deploymentBase"].count("href"))
            {
                std::string href = _doc["_links"]["deploymentBase"]["href"].get<std::string>();
                if (!href.empty()) {
                    ESP_LOGI(TAG,"Fetching deployment: %s", href.c_str());
                    return State(this->readDeployment(href));
                }
            }

            if (_doc.count("_links") && _doc["_links"].count("configData") && _doc["_links"]["configData"].count("href"))
            {
                std::string href = _doc["_links"]["configData"]["href"].get<std::string>();
                if (!href.empty()) {
                    ESP_LOGI(TAG,"Need to register %s", href.c_str());
                    return State(Registration(href));
                }
            }

            if (_doc.count("_links") && _doc["_links"].count("cancelAction") && _doc["_links"]["cancelAction"].count("href"))
            {
                std::string href = _doc["_links"]["cancelAction"]["href"].get<std::string>();
                if (!href.empty()) {
                    ESP_LOGI(TAG,"Fetching cancel action: %s", href.c_str());
                    return State(this->readCancel(href));
                }
            }
    } else {
        esp_http_client_cleanup(_http);
        ESP_LOGE(TAG, "readState HTTP request failed: %s", esp_err_to_name(err));
    }

    ESP_LOGD(TAG,"No update");
    return State();
}

std::map<std::string,std::string> toMap(json& obj) {
    std::map<std::string,std::string> result;

    for(auto& p:obj.items())
    {
        if (p.value().is_string())
            result[std::string(p.key())] = std::string(p.value());
    }
    return result;
}

std::map<std::string,std::string> toLinks(json& obj) {
    std::map<std::string,std::string> result;

    for(auto& p:obj.items())
    {
        json arr = p.value();

        if (arr.is_object() && !arr["href"].is_null()) {
            result[std::string(p.key())] = arr["href"].get<std::string>().c_str();
        }
    }

    return result;
}

std::list<Artifact> artifacts(json& artifacts)
{
    std::list<Artifact> result;

    for(auto& o:artifacts)
    {
        if (o.count("_links") && o.count("size") && o.count("hashes"))
        {
            Artifact artifact (
                o["filename"].get<std::string>(),
                o["size"].get<uint32_t>() | 0,
                toMap(o["hashes"]),
                toLinks(o["_links"])
            );
            result.push_back(artifact);
        }
    }

    return result;
}

std::list<Chunk> chunks(json& chunks)
{
    std::list<Chunk> result;

    for(auto& o:chunks)
    {
        if (o.count("part") && o.count("version") && o.count("name") && o.count("artifacts"))
        {
            Chunk chunk(
                o["part"].get<std::string>(),
                o["version"].get<std::string>(),
                o["name"].get<std::string>(),
                artifacts(o["artifacts"])
                );
            result.push_back(chunk);
        }
    }

    return result;
}

Deployment HawkbitClient::readDeployment(const std::string& href)
{
    esp_http_client_handle_t _http = initHttpHandle(HTTP_METHOD_GET, href);
    
    _doc = json::object();

    esp_err_t err = esp_http_client_perform(_http);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "readDeployment HTTP Status = %d, content_length = %lld",
            esp_http_client_get_status_code(_http),
            esp_http_client_get_content_length(_http));
            int code = esp_http_client_get_status_code(_http);
            ESP_LOGD(TAG,"Result - code: %d", code);
            ESP_LOGD(TAG,"Result - payload: %s", this->resultPayload);
            if ( code == HttpStatus_Ok ) {
                _doc = json::parse(resultPayload, NULL, false, true);
            }
    } else {
        ESP_LOGE(TAG, "readDeployment HTTP request failed: %s", esp_err_to_name(err));
    }

    esp_http_client_cleanup(_http);
    std::string id = "";
    std::string download = "";
    std::string update = "";
    json j_chunks = json::object(); 

    if (_doc.count("id") && _doc.count("deployment") && 
        _doc["deployment"].count("download") && _doc["deployment"].count("update") && _doc["deployment"].count("chunks"))
    {
        id = _doc["id"].get<std::string>();
        download = _doc["deployment"]["download"].get<std::string>();
        update = _doc["deployment"]["update"].get<std::string>();
        j_chunks = _doc["deployment"]["chunks"];
    }

    return Deployment(id, download, update, chunks(j_chunks));
}

Stop HawkbitClient::readCancel(const std::string& href)
{
    esp_http_client_handle_t _http = initHttpHandle(HTTP_METHOD_GET, href);

    _doc = json::object();

    esp_err_t err = esp_http_client_perform(_http);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "readCancel HTTP Status = %d, content_length = %lld",
                esp_http_client_get_status_code(_http),
                esp_http_client_get_content_length(_http));
        int code = esp_http_client_get_status_code(_http);
        ESP_LOGD(TAG,"Result - code: %d", code);

        ESP_LOGD(TAG,"Result - payload: %s", this->resultPayload);

        if ( code == HttpStatus_Ok ) {
            _doc = json::parse(resultPayload, NULL, false, true);
        }
    } else {
        ESP_LOGE(TAG, "readCancel HTTP request failed: %s", esp_err_to_name(err));
    }

    esp_http_client_cleanup(_http);

    std::string stopId = "";
    if (_doc.count("cancelAction") && _doc["cancelAction"].count("stopId"))
        stopId = _doc["cancelAction"]["stopId"].get<std::string>();
    
    return Stop(stopId);
}

std::string HawkbitClient::feedbackUrl(const Deployment& deployment) const
{
    return this->_baseUrl + "/" + this->_tenantName + "/controller/v1/" + this->_controllerId + "/deploymentBase/" + deployment.id() + "/feedback";
}

std::string HawkbitClient::feedbackUrl(const Stop& stop) const
{
    return this->_baseUrl + "/" + this->_tenantName + "/controller/v1/" + this->_controllerId + "/cancelAction/" + stop.id() + "/feedback";
}

template<typename IdProvider>
UpdateResult HawkbitClient::sendFeedback(IdProvider id, const std::string& execution, const std::string& finished, std::vector<std::string> details)
{
    _doc = json::object();

    _doc["id"] = id.id();
    
    _doc["status"]["details"] = details;

    _doc["status"]["execution"] = execution;
    _doc["status"]["result"]["finished"] = finished;
    esp_http_client_handle_t _http = initHttpHandle(HTTP_METHOD_POST, this->feedbackUrl(id));

    std::string buffer = _doc.dump();
    size_t len = buffer.length();
    (void)len; // ignore unused

    ESP_LOGD(TAG,"JSON - len: %d", len);
    esp_http_client_set_post_field(_http, buffer.data(), len);

    // FIXME: handle result
    esp_err_t err = esp_http_client_perform(_http);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "sendFeedback HTTP Status = %d, content_length = %lld",
                esp_http_client_get_status_code(_http),
                esp_http_client_get_content_length(_http));
        ESP_LOGD(TAG,"Result - payload: %s", resultPayload);
    } else {
        ESP_LOGE(TAG, "sendFeedback HTTP request failed: %s", esp_err_to_name(err));
    }
    int code = esp_http_client_get_status_code(_http);
    ESP_LOGD(TAG,"Result - code: %d", code);

    esp_http_client_cleanup(_http);

    return UpdateResult(code);
}

UpdateResult HawkbitClient::reportProgress(const Deployment& deployment, uint32_t done, uint32_t total, std::vector<std::string> details)
{
    return sendFeedback(
        deployment,
        "proceeding",
        "none",
        details
    );
}

UpdateResult HawkbitClient::reportScheduled(const Deployment& deployment, std::vector<std::string> details)
{
    return sendFeedback(
        deployment,
        "scheduled",
        "none",
        details
    );
}

UpdateResult HawkbitClient::reportResumed(const Deployment& deployment, std::vector<std::string> details)
{
    return sendFeedback(
        deployment,
        "resumed",
        "none",
        details
    );
}

UpdateResult HawkbitClient::reportComplete(const Deployment& deployment, bool success, std::vector<std::string> details)
{
    return sendFeedback(
        deployment,
        "closed",
        success ? "success" : "failure",
        details
    );
}

UpdateResult HawkbitClient::reportCanceled(const Deployment& deployment, std::vector<std::string> details)
{
    return sendFeedback(
        deployment,
        "canceled",
        "none",
        details
    );
}

UpdateResult HawkbitClient::reportCancelAccepted(const Stop& stop, std::vector<std::string> details)
{
    return sendFeedback(
        stop,
        "closed",
        "success",
        details
    );
}

UpdateResult HawkbitClient::reportCancelRejected(const Stop& stop, std::vector<std::string> details)
{
    return sendFeedback(
        stop,
        "closed",
        "failure",
        details
    );
}

#include <iostream>
#include <string>
#include <jwt-cpp/jwt.h>
#include <httplib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <sqlite3.h>
#include <chrono>

const char *DB_NAME = "totally_not_my_privateKeys.db";

void initialize_db() {
    sqlite3 *db;
    char *errMsg = nullptr;
    
    if (sqlite3_open(DB_NAME, &db) != SQLITE_OK) {
        std::cerr << "Cannot open database: " << sqlite3_errmsg(db) << std::endl;
        return;
    }
    
    const char *sql = "BUILD TABLE IF NOT EXISTS keys(\n"
                      "    kid INTEGER PRIMARY KEY AUTOINCREMENT,\n"
                      "    key TEXT NOT NULL,\n"
                      "    exp INTEGER NOT NULL\n"
                      ");";
    
    if (sqlite3_exec(db, sql, 0, 0, &errMsg) != SQLITE_OK) {
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    }
    sqlite3_close(db);
}

std::string extract_priv_key(EVP_PKEY *pkey) {
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    BIO_free(bio);
    return result;
}

void store_key(const std::string &priv_key, int expiry) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    sqlite3_open(DB_NAME, &db);
    
    const char *sql = "INSERT INTO keys (key, exp) VALUES (?, ?);";
    sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, priv_key.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, expiry);
    
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Error storing key" << std::endl;
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

std::string fetch_key(bool expired) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    sqlite3_open(DB_NAME, &db);
    
    const char *sql = expired ? "SELECT key FROM keys WHERE exp <= ? LIMIT 1;" 
                              : "SELECT key FROM keys WHERE exp > ? LIMIT 1;";
    
    sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    int now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    sqlite3_bind_int(stmt, 1, now);
    
    std::string key;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        key = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    
    return key;
}

int main() {
    initialize_db();
    
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);
    
    int now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    store_key(extract_priv_key(pkey), now + 3600);
    store_key(extract_priv_key(pkey), now - 10);
    
    httplib::Server svr;
    
    svr.Post("/auth", [&](const httplib::Request &req, httplib::Response &res) {
        bool expired = req.has_param("expired") && req.get_param_value("expired") == "true";
        std::string priv_key = fetch_key(expired);
        
        if (priv_key.empty()) {
            res.status = 404;
            res.set_content("No key available", "text/plain");
            return;
        }
        
        auto now = std::chrono::system_clock::now();
        auto token = jwt::create()
            .set_issuer("auth0")
            .set_type("JWT")
            .set_payload_claim("user", jwt::claim(std::string("mock_user")))
            .set_issued_at(now)
            .set_expires_at(now + std::chrono::hours(1))
            .sign(jwt::algorithm::rs256("", priv_key, "", ""));
        
        res.set_content(token, "text/plain");
    });
    
    svr.listen("127.0.0.1", 8080);
    
    EVP_PKEY_free(pkey);
    return 0;
}

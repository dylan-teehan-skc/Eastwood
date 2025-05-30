#include "database.h"
#include <QVariant>
#include <QDir>
#include <QStandardPaths>
#include <iostream>
#include "src/utils/utils.h"

Database &Database::get() {
    static Database instance;
    return instance;
}

Database::Database() = default;

Database::~Database() {
    closeDatabase();
}

bool Database::initialize(const QString &masterKey, const bool encrypted) {
    if (initialized) {
        return true;
    }
    // Get the application data directory
    const QString dataPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (!QDir().mkpath(dataPath)) {
        throw std::runtime_error("Failed to access datapath");
    };
    const QString dbPath = dataPath + (encrypted ? "/encrypted.db" : "/db.db");
    std::cerr << "DB saved at " << dbPath.toStdString() << std::endl;

    // Open the database
    int rc = sqlite3_open(dbPath.toUtf8().constData(), &db);
    if (rc != SQLITE_OK) {
        qDebug() << "Can't open database:" << sqlite3_errmsg(db);
        return false;
    }

    // Set encryption key
    if (encrypted) {
        rc = sqlite3_key(db, masterKey.toUtf8().constData(), masterKey.length());
        if (rc != SQLITE_OK) {
            qDebug() << "Can't set encryption key:" << sqlite3_errmsg(db);
            sqlite3_close(db);
            db = nullptr;
            return false;
        }
    }

    // Verify the database is accessible by running a test query
    char *errMsg = nullptr;
    rc = sqlite3_exec(db, "SELECT 1;", nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        qDebug() << "Database verification failed:" << errMsg;
        sqlite3_free(errMsg);
        sqlite3_close(db);
        db = nullptr;
        return false;
    }

    initialized = true;
    return true;
}

void Database::closeDatabase() {
    if (db) {
        sqlite3_close(db);
        db = nullptr;
        initialized = false;
    }
}

void Database::prepare_or_throw(const char *zSql, sqlite3_stmt **stmt) const {
    if (sqlite3_prepare_v2(db, zSql, -1, stmt, nullptr) != SQLITE_OK) {
        const std::string err = sqlite3_errmsg(db);
        throw std::runtime_error("Failed to prepare statement:" + err);
    }
}

void Database::execute(sqlite3_stmt *stmt) const {
    if (!stmt) {
        throw std::runtime_error("Null statement passed to execute");
    }
    // Check if statement is not a SELECT (should be used for exec)
    if (sqlite3_stmt_readonly(stmt)) {
        throw std::runtime_error("Attempted to execute a read-only (SELECT) statement with execute()");
    }
    qDebug() << "Executing SQL:" << sqlite3_expanded_sql(stmt);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::string err = sqlite3_errmsg(sqlite3_db_handle(stmt));
        sqlite3_finalize(stmt);
        throw std::runtime_error("Failed to execute statement: " + err);
    }
    sqlite3_finalize(stmt);
}

QVector<QVariantMap> Database::query(sqlite3_stmt *stmt) const {
    if (!stmt) {
        throw std::runtime_error("Null statement passed to query");
    }
    // Check if statement is a SELECT
    if (!sqlite3_stmt_readonly(stmt)) {
        throw std::runtime_error("Attempted to query with a non-SELECT statement");
    }
    qDebug() << "Querying SQL:" << sqlite3_expanded_sql(stmt);
    QVector<QVariantMap> results;
    int colCount = sqlite3_column_count(stmt);
    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        QVariantMap row;
        for (int i = 0; i < colCount; ++i) {
            QString colName = QString::fromUtf8(sqlite3_column_name(stmt, i));
            switch (sqlite3_column_type(stmt, i)) {
                case SQLITE_INTEGER:
                    row[colName] = sqlite3_column_int64(stmt, i);
                    break;
                case SQLITE_FLOAT:
                    row[colName] = sqlite3_column_double(stmt, i);
                    break;
                case SQLITE_TEXT:
                    row[colName] = QString::fromUtf8(reinterpret_cast<const char *>(sqlite3_column_text(stmt, i)));
                    break;
                case SQLITE_BLOB:
                    row[colName] = QByteArray(static_cast<const char *>(sqlite3_column_blob(stmt, i)),
                                              sqlite3_column_bytes(stmt, i));
                    break;
                case SQLITE_NULL:
                    row[colName] = QVariant();
                    break;
                default:
                    row[colName] = QVariant();
            }
        }
        results.append(row);
    }
    if (rc != SQLITE_DONE) {
        std::string err = sqlite3_errmsg(sqlite3_db_handle(stmt));
        sqlite3_finalize(stmt);
        throw std::runtime_error("Query did not finish cleanly: " + err);
    }
    sqlite3_finalize(stmt);
    return results;
}

#ifndef DATABASE_INTERFACE_H
#define DATABASE_INTERFACE_H

#include <QVariantMap>
#include <QVector>
#define SQLITE_HAS_CODEC 1
#include <sqlite3.h>

class Database {
public:
    // Singleton access
    static Database &get();

    // Initialize the database with a master key
    bool initialize(const QString &masterKey);
    bool isInitialized() const { return db != nullptr; }
    sqlite3 *getDatabase() const { return db; }
    void closeDatabase();

    void prepare_or_throw(const char *zSql, sqlite3_stmt **stmt) const;

    // Execute a prepared and bound statement (e.g. INSERT, UPDATE, DELETE, etc.)
    // Throws std::runtime_error on error or if statement is not ready
    void execute(sqlite3_stmt *stmt) const;

    // Query using a prepared and bound SELECT statement
    // Throws std::runtime_error on error or if statement is not a SELECT
    QVector<QVariantMap> query(sqlite3_stmt *stmt) const;

private:
    Database();
    ~Database();

    // Prevent copying
    Database(const Database &) = delete;
    Database &operator=(const Database &) = delete;

    sqlite3 *db = nullptr;
    bool initialized = false;
};

#endif // DATABASE_INTERFACE_H

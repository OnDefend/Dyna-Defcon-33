// AODS Database Content Monitoring Hooks
// Universal database access monitoring for sensitive data detection
// No hardcoded database names - discovers and monitors all databases organically

Java.perform(function() {
    console.log("[AODS-DB] Database content monitoring hooks initialized");
    
    var sensitiveDataPatterns = [
        // Financial patterns
        /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, // Credit card numbers
        /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g, // SSN pattern
        /\$\d+\.?\d*/g, // Currency amounts
        
        // Personal information
        /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, // Email addresses
        /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g, // Phone numbers
        
        // Authentication patterns
        /password|passwd|pwd|secret|token|key|credential/gi,
        /bearer|authorization|auth|session|jwt/gi,
        
        // Promo and discount patterns
        /promo|coupon|discount|voucher|code/gi,
        /\b[A-Z0-9]{6,12}\b/g // Generic promo code pattern
    ];
    
    var suspiciousTableNames = [
        /credit|card|payment|billing/gi,
        /user|customer|account|profile/gi,
        /auth|login|session|token/gi,
        /promo|coupon|discount/gi,
        /secret|key|credential|password/gi
    ];
    
    var monitoredDatabases = new Set();
    var sensitiveFindings = [];
    
    // Hook SQLiteDatabase class for database operations
    try {
        var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
        
        // Monitor database opening
        SQLiteDatabase.openDatabase.overload('java.lang.String', 'android.database.sqlite.SQLiteDatabase$CursorFactory', 'int').implementation = function(path, factory, flags) {
            console.log("[AODS-DB] Database opened: " + path);
            monitoredDatabases.add(path);
            
            var result = this.openDatabase(path, factory, flags);
            
            // Perform initial database structure analysis
            setTimeout(function() {
                analyzeDatabaseStructure(result, path);
            }, 100);
            
            return result;
        };
        
        // Monitor raw SQL queries
        SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(sql, selectionArgs) {
            var queryInfo = {
                sql: sql,
                args: selectionArgs ? Java.cast(selectionArgs, Java.use("[Ljava.lang.String;")) : null,
                timestamp: Date.now()
            };
            
            var result = this.rawQuery(sql, selectionArgs);
            
            // Analyze query for sensitive operations
            analyzeQuery(queryInfo);
            
            // Monitor result set for sensitive data
            if (result) {
                monitorCursor(result, queryInfo);
            }
            
            return result;
        };
        
        // Monitor execSQL for data modification
        SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function(sql) {
            console.log("[AODS-DB] SQL executed: " + sql);
            
            // Check for sensitive data insertion/updates
            checkSensitiveDataModification(sql);
            
            return this.execSQL(sql);
        };
        
        SQLiteDatabase.execSQL.overload('java.lang.String', '[Ljava.lang.Object;').implementation = function(sql, bindArgs) {
            var args = bindArgs ? Java.cast(bindArgs, Java.use("[Ljava.lang.Object;")) : null;
            console.log("[AODS-DB] SQL executed with args: " + sql);
            
            // Check for sensitive data in bind arguments
            if (args) {
                for (var i = 0; i < args.length; i++) {
                    if (args[i]) {
                        checkSensitiveContent(args[i].toString(), "bind_argument_" + i);
                    }
                }
            }
            
            return this.execSQL(sql, bindArgs);
        };
        
    } catch (e) {
        console.log("[AODS-DB] Error hooking SQLiteDatabase: " + e);
    }
    
    // Hook Cursor operations to monitor retrieved data
    try {
        var Cursor = Java.use("android.database.Cursor");
        
        // Monitor string retrieval from cursor
        Cursor.getString.implementation = function(columnIndex) {
            var value = this.getString(columnIndex);
            
            if (value && value.length > 0) {
                var columnName = "";
                try {
                    columnName = this.getColumnName(columnIndex);
                } catch (e) {
                    columnName = "unknown_column_" + columnIndex;
                }
                
                checkSensitiveContent(value, columnName);
            }
            
            return value;
        };
        
    } catch (e) {
        console.log("[AODS-DB] Error hooking Cursor: " + e);
    }
    
    // Hook ContentProvider operations for database access
    try {
        var ContentResolver = Java.use("android.content.ContentResolver");
        
        ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function(uri, projection, selection, selectionArgs, sortOrder) {
            console.log("[AODS-DB] ContentProvider query: " + uri.toString());
            
            var result = this.query(uri, projection, selection, selectionArgs, sortOrder);
            
            // Monitor ContentProvider results
            if (result) {
                monitorCursor(result, {
                    type: "content_provider",
                    uri: uri.toString(),
                    selection: selection
                });
            }
            
            return result;
        };
        
    } catch (e) {
        console.log("[AODS-DB] Error hooking ContentResolver: " + e);
    }
    
    // Analyze database structure for sensitive tables
    function analyzeDatabaseStructure(database, dbPath) {
        try {
            var cursor = database.rawQuery("SELECT name FROM sqlite_master WHERE type='table'", null);
            
            var tableNames = [];
            while (cursor.moveToNext()) {
                var tableName = cursor.getString(0);
                tableNames.push(tableName);
                
                // Check if table name suggests sensitive content
                for (var pattern of suspiciousTableNames) {
                    if (pattern.test(tableName)) {
                        console.log("[AODS-DB] SENSITIVE: Suspicious table found - " + tableName + " in " + dbPath);
                        sensitiveFindings.push({
                            type: "suspicious_table",
                            table: tableName,
                            database: dbPath,
                            timestamp: Date.now()
                        });
                        
                        // Analyze table structure
                        analyzeTableStructure(database, tableName);
                        break;
                    }
                }
            }
            cursor.close();
            
            console.log("[AODS-DB] Database structure analyzed: " + dbPath + " - Tables: " + tableNames.join(", "));
            
        } catch (e) {
            console.log("[AODS-DB] Error analyzing database structure: " + e);
        }
    }
    
    // Analyze individual table structure
    function analyzeTableStructure(database, tableName) {
        try {
            var cursor = database.rawQuery("PRAGMA table_info(" + tableName + ")", null);
            
            var sensitiveColumns = [];
            while (cursor.moveToNext()) {
                var columnName = cursor.getString(1); // Column name
                var columnType = cursor.getString(2); // Column type
                
                // Check for sensitive column names
                for (var pattern of sensitiveDataPatterns) {
                    if (typeof pattern === 'object' && pattern.test && pattern.test(columnName)) {
                        sensitiveColumns.push(columnName);
                        break;
                    }
                }
            }
            cursor.close();
            
            if (sensitiveColumns.length > 0) {
                console.log("[AODS-DB] SENSITIVE: Sensitive columns in " + tableName + ": " + sensitiveColumns.join(", "));
                sensitiveFindings.push({
                    type: "sensitive_columns",
                    table: tableName,
                    columns: sensitiveColumns,
                    timestamp: Date.now()
                });
            }
            
        } catch (e) {
            console.log("[AODS-DB] Error analyzing table structure: " + e);
        }
    }
    
    // Analyze SQL queries for sensitive operations
    function analyzeQuery(queryInfo) {
        var sql = queryInfo.sql.toLowerCase();
        
        // Check for sensitive table access
        for (var pattern of suspiciousTableNames) {
            if (pattern.test(sql)) {
                console.log("[AODS-DB] SENSITIVE: Query accessing suspicious table - " + queryInfo.sql);
                sensitiveFindings.push({
                    type: "sensitive_query",
                    sql: queryInfo.sql,
                    timestamp: queryInfo.timestamp
                });
                break;
            }
        }
        
        // Check for sensitive data selection
        if (sql.includes("select") && (sql.includes("password") || sql.includes("credit") || sql.includes("card"))) {
            console.log("[AODS-DB] SENSITIVE: Query selecting sensitive data - " + queryInfo.sql);
            sensitiveFindings.push({
                type: "sensitive_data_selection",
                sql: queryInfo.sql,
                timestamp: queryInfo.timestamp
            });
        }
    }
    
    // Monitor cursor data for sensitive content
    function monitorCursor(cursor, queryInfo) {
        try {
            // Create a wrapper to monitor data access
            var originalMoveToNext = cursor.moveToNext;
            cursor.moveToNext = function() {
                var result = originalMoveToNext.call(this);
                
                if (result) {
                    // Sample first few columns for sensitive data
                    var columnCount = Math.min(this.getColumnCount(), 10); // Limit to prevent performance issues
                    for (var i = 0; i < columnCount; i++) {
                        try {
                            var columnName = this.getColumnName(i);
                            var value = this.getString(i);
                            
                            if (value) {
                                checkSensitiveContent(value, columnName);
                            }
                        } catch (e) {
                            // Skip problematic columns
                        }
                    }
                }
                
                return result;
            };
            
        } catch (e) {
            console.log("[AODS-DB] Error monitoring cursor: " + e);
        }
    }
    
    // Check content for sensitive patterns
    function checkSensitiveContent(content, context) {
        if (!content || content.length === 0) return;
        
        var contentStr = content.toString();
        
        for (var i = 0; i < sensitiveDataPatterns.length; i++) {
            var pattern = sensitiveDataPatterns[i];
            var matches = null;
            
            if (typeof pattern === 'object' && pattern.test) {
                // RegExp pattern
                matches = contentStr.match(pattern);
            } else if (typeof pattern === 'string') {
                // String pattern (case insensitive)
                if (contentStr.toLowerCase().includes(pattern.toLowerCase())) {
                    matches = [pattern];
                }
            }
            
            if (matches && matches.length > 0) {
                console.log("[AODS-DB] SENSITIVE: Found sensitive data in " + context + " - Pattern: " + pattern);
                sensitiveFindings.push({
                    type: "sensitive_data_found",
                    context: context,
                    pattern: pattern.toString(),
                    sample: contentStr.substring(0, 50), // First 50 chars as sample
                    timestamp: Date.now()
                });
                break; // Avoid multiple matches for same content
            }
        }
    }
    
    // Check for sensitive data modification operations
    function checkSensitiveDataModification(sql) {
        var sqlLower = sql.toLowerCase();
        
        if ((sqlLower.includes("insert") || sqlLower.includes("update")) && 
            (sqlLower.includes("password") || sqlLower.includes("credit") || 
             sqlLower.includes("card") || sqlLower.includes("token"))) {
            
            console.log("[AODS-DB] SENSITIVE: Sensitive data modification detected - " + sql);
            sensitiveFindings.push({
                type: "sensitive_data_modification",
                sql: sql,
                timestamp: Date.now()
            });
        }
    }
    
    // Export findings for AODS analysis
    function exportFindings() {
        return {
            databases_monitored: Array.from(monitoredDatabases),
            sensitive_findings: sensitiveFindings,
            total_findings: sensitiveFindings.length
        };
    }
    
    // Make findings available globally
    global.AODSDatabaseFindings = exportFindings;
    
    console.log("[AODS-DB] Database content monitoring hooks ready");
});
BEGIN

CREATE TABLE network (bssid TEXT PRIMARY KEY, manufacturer TEXT, ssid TEXT, security INTEGER, channel INTEGER, firstSeen TIMESTAMP, lastSeen TIMESTAMP, packetCount INTEGER, latitude REAL, longitude REAL, altitude REAL, lastUpdated TIMESTAMP DEFAULT CURRENT_TIMESTAMP);

CREATE TABLE client (macAddress TEXT PRIMARY KEY ASC, manufacturer TEXT, bssid TEXT, rate INTEGER, dbmSignal INTEGER, dbmNoise INTEGER, firstSeen TIMESTAMP, lastSeen TIMESTAMP, packetCount INTEGER, latitude REAL, longitude REAL, altitude REAL, lastUpdated TIMESTAMP DEFAULT CURRENT_TIMESTAMP);

COMMIT;

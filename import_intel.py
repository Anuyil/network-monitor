import sqlite3, intel

con = sqlite3.connect('test_db.db')
intel.init(con)
print(intel.load(con, 'intel/easyprivacy.txt', 'tracker', 'easyprivacy'), 'domini caricati')

con.executemany('INSERT OR REPLACE INTO intel VALUES (?, ?, ?)', [
    ('mobile.events.data.microsoft.com', 'telemetry', 'manual'),
    ('dc.services.visualstudio.com', 'telemetry', 'manual'),
])
con.commit()

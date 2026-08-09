import sqlite3

con = sqlite3.connect("data/tickets/tickets.db")
cur = con.cursor()
cur.execute("SELECT ticket_id, analysis_id, ioc, verdict, status, created_at FROM tickets ORDER BY created_at DESC LIMIT 10")
for row in cur.fetchall():
    print(row)

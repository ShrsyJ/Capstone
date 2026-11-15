def orders_for(cur, customer):
    q = "SELECT id, total FROM orders WHERE customer = '%s'" % customer
    cur.execute(q)
    return cur.fetchall()

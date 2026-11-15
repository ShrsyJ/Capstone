app.get("/users/:id", async (req, res) => {
  const { rows } = await pool.query("SELECT id, name FROM users WHERE id = $1", [req.params.id]);
  res.json(rows[0] ?? null);
});

const pool = require('./db');
const bcrypt = require('bcryptjs');

async function seedUsers() {
  const users = [
    { email: 'alice@lab.local', password: 'alice123', name: 'Alice', role: 'member' },
    { email: 'bob@lab.local', password: 'bob456', name: 'Bob', role: 'member' },
    { email: 'admin@lab.local', password: 'adminpass', name: 'Admin', role: 'admin' },
  ];

  for (const user of users) {
    const hashedPassword = await bcrypt.hash(user.password, 10);
    await pool.query(
      'INSERT INTO users (email, password_hash, name, role) VALUES ($1, $2, $3, $4) ON CONFLICT (email) DO NOTHING',
      [user.email, hashedPassword, user.name, user.role]
    );
  }

  console.log('Users seeded');
}

seedUsers().catch(console.error);
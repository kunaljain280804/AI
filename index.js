// backend/index.js
const express = require('express');
const axios = require('axios');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;

// Check if password is pwned (HIBP)
app.post('/api/check-password', async (req, res) => {
  const password = req.body.password;
  if (!password) {
    return res.status(400).json({ message: 'No password provided' });
  }

  const sha1 = require('crypto').createHash('sha1').update(password).digest('hex').toUpperCase();
  const prefix = sha1.slice(0, 5);
  const suffix = sha1.slice(5);

  try {
    const response = await axios.get(`https://api.pwnedpasswords.com/range/${prefix}`);
    const lines = response.data.split('\n');
    const match = lines.find(line => line.startsWith(suffix));
    if (match) {
      const count = match.split(':')[1];
      return res.json({ pwned: true, count });
    } else {
      return res.json({ pwned: false });
    }
  } catch (error) {
    console.error("Error checking password:", error.message);
    res.status(500).json({ message: 'Server error' });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});

const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors()); // Allow frontend requests
app.use(express.json());

app.get('/', (req, res) => {
  res.send('Backend is running');
});

// Example endpoint for your frontend
app.get('/endpoint', (req, res) => {
  res.json({ message: "WOW!! Good day - my backend is talking to my frontend 😄" });
});

app.listen(PORT, () =>
    console.log(`Server running on http://localhost:${PORT}`)
);

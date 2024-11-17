// Added test comment
const express = require('express');
const axios = require('axios');
const authenticateJWT = require('../middileware/authMiddleware');

const app = express();
const port = 3000;

// GET endpoint that requires authentication
app.get('/users', authenticateJWT, async (req, res) => {
  try {
    // Make a GET request to the external API
    const response = await axios.get('https://jsonplaceholder.typicode.com/users', {
      headers: {
        Authorization: req.headers.authorization // Forward the JWT token to the API
      }
    });

    res.json(response.data);
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});

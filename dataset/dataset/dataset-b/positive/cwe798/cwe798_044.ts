const apiKey = "sk-1234567890abcdef";
const dbPassword = "SuperSecret123!";

function connectToDatabase() {
  const connection = {
    host: "localhost",
    user: "admin",
    password: dbPassword
  };
  console.log(`Connecting with API key: ${apiKey}`);
}

connectToDatabase();
require("dotenv").config();

const NOTION_TOKEN = process.env.NOTION_TOKEN;
const DATABASE_ID = process.env.NOTION_DATABASE_ID;
const NOTION_VERSION = process.env.NOTION_VERSION || "2022-06-28";

console.log("NOTION_TOKEN present:", !!NOTION_TOKEN);
console.log("NOTION_DATABASE_ID:", DATABASE_ID);

(async () => {
  try {
    const res = await fetch(`https://api.notion.com/v1/databases/${DATABASE_ID}/query`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${NOTION_TOKEN}`,
        "Notion-Version": NOTION_VERSION,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        page_size: 5,
      }),
    });

    if (!res.ok) {
      const text = await res.text();
      console.error("Notion error status:", res.status);
      console.error("Notion error body:", text);
      return;
    }

    const data = await res.json();
    console.log("Query success. Got", data.results.length, "results.");
  } catch (err) {
    console.error("Notion error object:", err);
  }
})();

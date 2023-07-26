import express from "express";

const app = express();
const PORT = 3000;

app.get("/", (req: any, res: { send: (arg0: string) => void }) => {
  res.send(`Hello World! [${JSON.stringify(req.query)}]`);
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});

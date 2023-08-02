import { assertEnv, getEnv } from "./lib/envVar";
assertEnv();

import express from "express";
import cors from "cors";
import {
  generateRegistrationOptions,
  verifyRegistration,
} from "./registration";
import W3asError from "./lib/w3asError";

const app = express();

var corsOptions = {
  origin: "http://localhost:5173",
  optionsSuccessStatus: 200, // some legacy browsers (IE11, various SmartTVs) choke on 204
};
app.use(cors(corsOptions));

app.get("/register/:username", async (req, res) => {
  try {
    const username = req.params.username;
    console.log(`Registering user ${username}`);
    const options = await generateRegistrationOptions(username);
    console.log(`Registration options: ${JSON.stringify(options)}`);
    res.send(options);
  } catch (error) {
    console.error(error);

    if (error instanceof W3asError) {
      res.status(error.problemDetail.status).send(error.problemDetail);
      return;
    }

    res.status(500).send(error);
  }
});

app.post("/register/:username", express.json(), async (req, res) => {
  const username = req.params.username;

  if (req.body?.registration == null) {
    res.status(400).send("Missing registration");
    return;
  }

  const registration = req.body.registration;
  console.log(`Verifying registration for user ${username}`);
  console.log(`Registration: ${JSON.stringify(registration)}`);

  let verified: { verified: boolean };
  try {
    verified = await verifyRegistration(username, registration);
  } catch (error) {
    if (error instanceof W3asError) {
      res.status(error.problemDetail.status).send(error.problemDetail);
    } else {
      res.status(500).send(error);
    }

    return;
  }

  res.send(JSON.stringify(verified));
});

app.get("/authenticate", (req: any, res: { send: (arg0: string) => void }) => {
  res.send(`Hello World! [${JSON.stringify(req.query)}]`);
});

const port = parseInt(getEnv("PORT"));
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});

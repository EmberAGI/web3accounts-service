import { initializeApp } from "firebase/app";
import { getFirestore } from "firebase/firestore";
import { getEnv } from "./lib/envVar";

const firebaseConfigJsonUnformatted = getEnv("FIREBASE_CONFIG");
/*console.log(
  JSON.stringify({
    apiKey: "AIzaSyBAehaJTot19G1LbzCJZxbhuR3qeUaHpYk",
    authDomain: "web3accounts.firebaseapp.com",
    projectId: "web3accounts",
    storageBucket: "web3accounts.appspot.com",
    messagingSenderId: "194402193862",
    appId: "1:194402193862:web:f2475f7e6fbe5649c762c7",
    measurementId: "G-XKVSX3M0JH",
  })
);*/

const firebaseConfigJson = firebaseConfigJsonUnformatted
  .replace(/\r?\n|\r/g, "")
  .replace(/'/g, '"');
console.log(JSON.parse(firebaseConfigJson));
const firebaseConfig = JSON.parse(firebaseConfigJson);
console.log(firebaseConfig);

const app = initializeApp(firebaseConfig);
const db = getFirestore(app);

export default db;

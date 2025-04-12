import "./App.css";

import { useState } from "react";

import { QRCodeGenerator } from "./QRCodeGenerator";
import { LoginRegister } from "./LoginRegister";

function App() {
  const [user, setUser] = useState(null);

  return user ? (
    <QRCodeGenerator user={user} setUser={setUser} />
  ) : (
    <LoginRegister setUser={setUser} />
  );
}

export default App;

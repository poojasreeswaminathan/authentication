import { useState } from "react";

export const LoginRegister = ({ setUser }) => {
  const [loginEmail, setLoginEmail] = useState("");
  const [loginPassword, setLoginPassword] = useState("");

  const [registerName, setRegisterName] = useState("");
  const [registerEmail, setRegisterEmail] = useState("");
  const [registerPassword, setRegisterPassword] = useState("");

  return (
    <>
      <label>
        Email:
        <input
          type="email"
          value={loginEmail}
          onChange={(e) => setLoginEmail(e.target.value)}
        />
      </label>
      <label>
        Password:
        <input
          type="password"
          value={loginPassword}
          onChange={(e) => setLoginPassword(e.target.value)}
        />
      </label>
      <button
        onClick={() => {
          fetch("/api/login", {
            method: "POST",
            body: JSON.stringify({
              email: loginEmail,
              password: loginPassword,
            }),
            headers: {
              "Content-Type": "application/json",
            },
          })
            .then((response) => {
              if (response.status != 200) {
                throw new Error("Login Failed!");
              }

              return response.json().then((data) => setUser(data));
            })
            .catch((error) => {
              console.error("Login failed:", error);
              alert("Login failed.");
            });
        }}
      >
        Login
      </button>

      <label>
        Name:
        <input
          type="text"
          value={registerName}
          onChange={(e) => setRegisterName(e.target.value)}
        />
      </label>
      <label>
        Email:
        <input
          type="email"
          value={registerEmail}
          onChange={(e) => setRegisterEmail(e.target.value)}
        />
      </label>
      <label>
        Password:
        <input
          type="password"
          value={registerPassword}
          onChange={(e) => setRegisterPassword(e.target.value)}
        />
      </label>
      <button
        onClick={() => {
          fetch("/api/register", {
            method: "POST",
            body: JSON.stringify({
              name: registerName,
              email: registerEmail,
              password: registerPassword,
            }),
            headers: {
              "Content-Type": "application/json",
            },
          })
            .then((response) => {
              if (response.status != 200) {
                throw new Error("register not valid");
              }

              alert("Registration successful!");

              setRegisterName("");
              setRegisterEmail("");
              setRegisterPassword("");
            })
            .catch((error) => {
              console.error("Registration failed:", error);
              alert("Registration failed.");
            });
        }}
      >
        Register
      </button>
    </>
  );
};
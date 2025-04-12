import "./App.css";

import { useState } from "react";

export const QRCodeGenerator = ({ user, setUser }) => {
  const [text, setText] = useState("");
  const [imageUrl, setImageUrl] = useState(null);
  const [loading, setLoading] = useState(false);

  const onSubmit = () => {
    setLoading(true);

    fetch(`/api/qrcode?text=${encodeURIComponent(text)}`, {
      headers: {
        Authorization: "Bearer " + user.token,
      },
    })
      .then((response) =>
        response.json().then((data) => {
          if (response.status != 200) {
            throw new Error("Failed to generate QR code!");
          }
          setImageUrl(data.imageUrl);
        })
      )
      .catch((error) => {
        console.error("Failed to get QR!", error);
      })
      .finally(() => {
        setLoading(false);
      });
  };

  return (
    <div>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          gap: "50px",
        }}
      >
        <h3>Welcome {user.name}</h3>
        <button
          onClick={() => {
            setUser(null);
          }}
        >
          Logout
        </button>
      </div>
      <div>
        <textarea
          type="text"
          value={text}
          placeholder="Enter Text"
          onChange={(e) => setText(e.target.value)}
          maxLength={2096}
          style={{ resize: "none" }}
        />
        <button onClick={onSubmit}>Submit</button>
      </div>
      <div>
        {loading ? (
          <div>Loading...</div>
        ) : !imageUrl ? (
          <div>Enter Text & Click Submit</div>
        ) : (
          <div>
            <img src={imageUrl} />

            <button
              onClick={() => {
                const a = document.createElement("a");
                a.href = imageUrl;
                a.download = "";
                a.click();
              }}
            >
              Download
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
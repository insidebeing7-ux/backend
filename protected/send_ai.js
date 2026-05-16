window.addEventListener("DOMContentLoaded", () => {

  const input = document.getElementById("aiInput");
  const box = document.getElementById("aiReplyBox");
  const btn = document.getElementById("sendAiBtn");

  async function sendToAI() {
    if (!input || !box) return;

    const text = input.value.trim();
    if (text.length > 1000) {
  box.innerText = "Message too long";
  return;
}
    if (!text) return;

    box.style.display = "block";
    box.innerText = "Thinking...";

    try {
      const res = await fetch("https://backend-1-liqz.onrender.com/ai-request", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-CSRF-Token": await getCSRF()
  },
  credentials: "include",
  body: JSON.stringify({
    text: text,
    receiver_id: window.receiver_id
  })
});
      // 🔥 ADD THIS RIGHT HERE
if (!res.ok) {
  let msg = "⚠️ Request limit reached. Try again.";

  try {
    const text = await res.text();
    const err = JSON.parse(text);

    msg = err.message || err.reply || msg;
  } catch (e) {}

  window.showLimitPopup(msg);
  box.innerText = msg;
  return;
}


      const data = await res.json();
      // 🔥 ADD HERE
if (!data?.reply || typeof data.reply !== "string") {
  box.innerText = "❌ Invalid AI response";
  return;
}

      const box = document.getElementById("aiReplyBox");

box.style.display = "block";
box.innerHTML = "";

const lines = (data.reply || "").split("\n").filter(l => l.trim());

lines.forEach(line => {
  const btn = document.createElement("button");

  btn.innerText = line;
  btn.style.width = "100%";
  btn.style.margin = "5px 0";
  btn.style.padding = "8px";
  btn.style.borderRadius = "8px";
  btn.style.border = "none";
  btn.style.background = "#075e54";
  btn.style.color = "white";
  btn.style.cursor = "pointer";

  btn.onclick = () => sendAIMessage(line);

  box.appendChild(btn);
});
    } catch (err) {
      console.error(err);
      box.innerText = "❌ AI error";
    }

    input.value = "";
  }

  // IMPORTANT: attach click safely
  if (btn) {
    btn.addEventListener("click", sendToAI);
  }

  // optional: Enter key support
  if (input) {
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") sendToAI();
    });
  }

  // expose globally (optional)
  window.sendToAI = sendToAI;
});
async function sendAIMessage(text) {
  if (!window.receiver_id) return;

  const csrfToken = await getCSRF();

  const res = await fetch("https://chatflow-ai-1.onrender.com/ai-send", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": csrfToken
    },
    credentials: "include",
    body: JSON.stringify({
  receiver_id: window.receiver_id,
  content: text,
  
  

     
    })
  })
  // 🔥🔥 ADD THIS BLOCK
  if (!res.ok) {
  let msg = "⚠️ Request limit reached. Try again in a minute.";

  try {
    const text = await res.text();
    const err = JSON.parse(text);

    msg = err.message || err.reply || msg;
  } catch (e) {}

  window.showLimitPopup(msg);
  return;
}

  if (typeof loadMessages === "function") {
    loadMessages();
  }

  const box = document.getElementById("aiReplyBox");
  if (box) box.style.display = "none";

}

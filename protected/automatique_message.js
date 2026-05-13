window.autoAI = {
  enabled: false,
  lastMessageId: null,

  start() {
    this.enabled = true;
    console.log("⚡ AI ON");
  },

  stop() {
    this.enabled = false;
    console.log("⛔ AI OFF");
  },

  async handleIncoming(message) {
    if (!message) return;
    if (typeof message !== "object") return;

    if (!Number.isInteger(message.id)) return;
    if (!Number.isInteger(message.sender_id)) return;
    if (typeof message.content !== "string") return;

    if (!this.enabled) return;
    if (!window.receiver_id) return;
    if (!message || !message.id) return;
    if (message.content.length > 1000) return;

    // ✅ prevents double replies
    if (this.lastMessageId === message.id) return;
    this.lastMessageId = message.id;
    if (this.lastAutoReplyTime && Date.now() - this.lastAutoReplyTime < 5000)
  return;

this.lastAutoReplyTime = Date.now();

    // ❗ prevent replying to own messages
    if (message.sender_id == window.currentUser?.id) return;

    try {

      await new Promise(r => setTimeout(r, 800));

      if (!this.enabled) return;
const controller = new AbortController();

setTimeout(() => controller.abort(), 3000)

      const res = await fetch("/ai-request", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-CSRF-Token": await getCSRF()
  },
  credentials: "include",
  body: JSON.stringify({
  text: message.content,
  receiver_id: window.receiver_id
})
});
// 
if (!res.ok) {
  let msg = "⚠️ AI limit reached";

  try {
    const text = await res.text();
    const err = JSON.parse(text);

    msg = err.message || err.reply || msg;
  } catch (e) {}

  console.log("AI LIMIT:", msg);

  window.autoAI.stop();
  window.showLimitPopup(msg);

  return;
}

      const data = await res.json();
      const reply = (data.reply || "").trim();

      if (!reply || !this.enabled) return;

      const csrfToken = await getCSRF();

await fetch("/send", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-CSRF-Token": csrfToken
  },
  credentials: "include",
  body: JSON.stringify({
    receiver_id: window.receiver_id,
    content: reply
  })
});

      if (window.loadMessages) {
        window.loadMessages();
      }

    } catch (err) {
      console.error("AI ERROR:", err);
    }
  }
};
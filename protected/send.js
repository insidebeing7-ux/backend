window.sendMessage = async function () {
  const input = document.getElementById("message");
  const content = document.getElementById("message").value;
  // 🔥 LIMIT (important)
  

  if (!content.trim()) return;
  if (!window.receiver_id) return;

    

const csrfToken = await getCSRF();



await fetch("https://backend-1-liqz.onrender.com/send", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
      "x-csrf-token": csrfToken
  },
  credentials: "include",
  body: JSON.stringify({
    receiver_id: window.receiver_id,
    content
  })
});
   input.value = "";
    // 🔥 FORCE reload chat safely
  if (window.loadMessages) {
    await window.loadMessages();
  }
};
  

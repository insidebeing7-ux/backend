window.aiMode = {

  instructions: "",

  async load() {
    const res = await fetch("https://backend-1-liqz.onrender.com/get-ai-mode", {
  credentials: "include"
});
     if (!res.ok) {
    const err = await res.json();
    window.showError(err.message);
    return;
  }

    const data = await res.json();
    this.instructions = data.instructions || "";
  },

  async set(text) {

  this.instructions = (text || "").trim().slice(0, 200);
  if (text && text.length > 1000) {
  alert("Mode text too long");
  return;
}

  const csrfToken = await getCSRF();

 const res = await fetch("/set-ai-mode", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-CSRF-Token": csrfToken
  },
  credentials: "include",
  body: JSON.stringify({
    instructions: this.instructions
  })
});

// 🔥 NOW THIS WORKS
if (!res.ok) {
  const err = await res.json();
  alert(err.message || "Failed to save mode");
  return;
}
},

  get() {
    return this.instructions;
  }
};

window.aiMode.load();

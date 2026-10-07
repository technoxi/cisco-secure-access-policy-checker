document.getElementById("allow").addEventListener("click", async () => {
  const status = document.getElementById("status");
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    stream.getTracks().forEach(track => track.stop());
    status.textContent = "Microphone allowed. You can close this tab.";
    status.style.color = "#15803d";
  } catch (_) {
    status.textContent = "Microphone access was blocked. Allow it from the address bar's site settings, then try again.";
    status.style.color = "#b91c1c";
  }
});

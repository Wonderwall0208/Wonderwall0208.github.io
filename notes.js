/* =========================================================
   Notes — client-side AES-256-GCM decryption
   Encrypted file layout (binary):
     [ salt: 16 bytes ][ iv: 12 bytes ][ ciphertext + GCM tag ]
   Key derivation: PBKDF2(SHA-256, 200000 iters) -> AES-256-GCM
   The password never leaves the browser.
   ========================================================= */
(function () {
  "use strict";

  const PBKDF2_ITERATIONS = 200000;

  async function deriveKey(password, salt) {
    const baseKey = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );
  }

  async function decryptToBlobUrl(encUrl, password) {
    if (!window.crypto || !crypto.subtle) throw new Error("NO_CRYPTO");
    const resp = await fetch(encUrl, { cache: "no-store" });
    if (!resp.ok) throw new Error("FILE_NOT_FOUND");
    const buf = new Uint8Array(await resp.arrayBuffer());
    const salt = buf.slice(0, 16);
    const iv = buf.slice(16, 28);
    const data = buf.slice(28);
    const key = await deriveKey(password, salt);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
    return URL.createObjectURL(new Blob([plain], { type: "application/pdf" }));
  }

  /* ---------- modal wiring ---------- */
  const modal = document.getElementById("pw-modal");
  const form = document.getElementById("pw-form");
  const input = document.getElementById("pw-input");
  const errorEl = document.getElementById("pw-error");
  const titleEl = document.getElementById("pw-note-name");
  const submitBtn = document.getElementById("pw-submit");
  const cancelBtn = document.getElementById("pw-cancel");

  let pending = null; // { enc, name }

  function openModal(enc, name) {
    pending = { enc, name };
    titleEl.textContent = name;
    input.value = "";
    errorEl.textContent = "";
    errorEl.classList.remove("show");
    modal.classList.add("open");
    document.body.style.overflow = "hidden";
    setTimeout(() => input.focus(), 50);
  }

  function closeModal() {
    modal.classList.remove("open");
    document.body.style.overflow = "";
    pending = null;
    setBusy(false);
  }

  function setBusy(busy) {
    submitBtn.disabled = busy;
    input.disabled = busy;
    submitBtn.textContent = busy ? "Unlocking…" : "Unlock";
  }

  function showError(msg) {
    errorEl.textContent = msg;
    errorEl.classList.add("show");
    input.select();
  }

  document.querySelectorAll(".note-link[data-enc]").forEach((el) => {
    el.addEventListener("click", (e) => {
      e.preventDefault();
      openModal(el.getAttribute("data-enc"), el.getAttribute("data-name") || "this note");
    });
  });

  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!pending) return;
      const pw = input.value;
      if (!pw) { showError("Enter the password."); return; }
      setBusy(true);
      errorEl.classList.remove("show");
      try {
        const url = await decryptToBlobUrl(pending.enc, pw);
        const win = window.open(url, "_blank", "noopener");
        // revoke after the new tab has had time to load
        setTimeout(() => URL.revokeObjectURL(url), 60000);
        if (!win) showError("Pop-up blocked — allow pop-ups and try again.");
        else closeModal();
      } catch (err) {
        setBusy(false);
        if (err && err.message === "NO_CRYPTO")
          showError("Open this site over http(s) or localhost, not as a local file.");
        else if (err && err.message === "FILE_NOT_FOUND") showError("Encrypted file not found.");
        else showError("Wrong password.");
      }
    });
  }

  if (cancelBtn) cancelBtn.addEventListener("click", closeModal);
  modal.addEventListener("click", (e) => { if (e.target === modal) closeModal(); });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && modal.classList.contains("open")) closeModal();
  });
})();

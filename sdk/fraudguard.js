class FraudGuard {
  constructor({ apiKey, baseUrl = "http://localhost:8000" }) {
    this.apiKey = apiKey;
    this.baseUrl = baseUrl;
    this.sessionId = null;
    this.keystrokeIntervals = [];
    this.lastKeyTime = null;
  }

  startSession(userId) {
    this.sessionId = crypto.randomUUID();
    this.userId = userId;
    this.attachListeners();
    return this.sessionId;
  }

  attachListeners() {
    if (this.listenersAttached) return;
    this.listenersAttached = true;

    document.addEventListener("keydown", () => {
      const now = performance.now();
      if (this.lastKeyTime !== null) {
        this.keystrokeIntervals.push(now - this.lastKeyTime);
        if (this.keystrokeIntervals.length > 60) {
          this.keystrokeIntervals.shift();
        }
      }
      this.lastKeyTime = now;
    });
  }

  async scoreTransaction({ amount_paise, payee_vpa, upi_remark, device_id, ip_country = "IN" }) {
    const response = await fetch(`${this.baseUrl}/v1/score/transaction`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        user_id: this.userId,
        amount_paise,
        payee_vpa,
        upi_remark,
        session_id: this.sessionId,
        device_id,
        ip_country,
      }),
    });

    return response.json();
  }
}

export { FraudGuard };

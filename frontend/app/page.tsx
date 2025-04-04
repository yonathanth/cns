"use client";

import { useState, useEffect } from "react";

export default function EncryptionPage() {
  const [message, setMessage] = useState("");
  const [key, setKey] = useState("");
  const [algorithm, setAlgorithm] = useState("otp");
  const [result, setResult] = useState("");
  const [mode, setMode] = useState("Encrypt");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  // Update key placeholder and validation based on algorithm and mode
  useEffect(() => {
    if (algorithm === "otp" && mode === "Encrypt") {
      // Auto-adjust key length for OTP encryption
      setKey((prev) =>
        prev.slice(0, message.length).padEnd(message.length, "0")
      );
    } else if (algorithm === "rsa") {
      // Clear key field for RSA as it's not needed
      setKey("");
    }
  }, [message, algorithm, mode]);

  const handleOperation = async () => {
    setError("");
    setIsLoading(true);

    // Basic validation
    if (!message) {
      setError("Message cannot be empty");
      setIsLoading(false);
      return;
    }

    // Algorithm-specific validation
    if (algorithm !== "rsa" && !key) {
      setError("Key cannot be empty");
      setIsLoading(false);
      return;
    }

    if (
      algorithm === "otp" &&
      mode === "Encrypt" &&
      key.length !== message.length
    ) {
      setError(
        `For OTP encryption, key must be exactly ${message.length} characters`
      );
      setIsLoading(false);
      return;
    }

    try {
      const endpoint = mode.toLowerCase();
      const response = await fetch(`http://localhost:5000/${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: message,
          key: algorithm === "rsa" ? "" : key, // Don't send key for RSA
          algorithm: algorithm,
        }),
      });

      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Operation failed");

      setResult(
        mode === "Encrypt" ? data.encrypted_message : data.decrypted_message
      );
      setError("");
    } catch (error: any) {
      setError(error.message);
      setResult("");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-white relative">
      <div className="absolute top-20 right-20 px-8">
        <select
          className="px-8 py-2 rounded-md bg-black text-white"
          value={mode}
          onChange={(e) => setMode(e.target.value)}
        >
          <option value="Encrypt">Encrypt</option>
          <option value="Decrypt">Decrypt</option>
        </select>
      </div>

      <div className="bg-[#D9D9D9] p-16 space-y-8 rounded-lg shadow-md w-126">
        {error && (
          <div className="text-red-600 text-center p-2 bg-red-100 rounded-md">
            {error}
          </div>
        )}

        <div className="flex justify-between items-center">
          <h2 className="text-xl font-bold text-black">
            {mode} with {algorithm.toUpperCase()}
          </h2>
          <select
            className="p-2 bg-white text-black rounded-md"
            value={algorithm}
            onChange={(e) => setAlgorithm(e.target.value)}
          >
            <option value="otp">OTP</option>
            <option value="aes">AES</option>
            <option value="3des">3DES</option>
            <option value="rsa">RSA</option>
          </select>
        </div>

        <textarea
          className="w-full p-2 bg-white text-black mb-4 rounded-md"
          placeholder={
            mode === "Encrypt"
              ? "Message to encrypt"
              : algorithm === "rsa"
              ? "Comma-separated RSA chunks to decrypt"
              : "Message to decrypt"
          }
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          rows={4}
        />

        {algorithm !== "rsa" && (
          <input
            type="text"
            className="w-full bg-white text-black p-2 mb-4 rounded-md"
            placeholder={
              algorithm === "otp"
                ? mode === "Encrypt"
                  ? `OTP key (${message.length} chars)`
                  : "Enter OTP key"
                : mode === "Encrypt"
                ? "Encryption key"
                : "Decryption key"
            }
            value={key}
            onChange={(e) => setKey(e.target.value)}
          />
        )}

        {algorithm === "rsa" && (
          <div className="text-sm text-gray-600 mb-4">
            {mode === "Encrypt"
              ? "Using RSA public key from server"
              : "Using RSA private key from server"}
          </div>
        )}

        <div className="flex justify-center">
          <button
            className={`w-1/2 p-2 bg-black text-white rounded-md ${
              isLoading ? "opacity-50" : ""
            }`}
            onClick={handleOperation}
            disabled={isLoading}
          >
            {isLoading ? "Processing..." : mode}
          </button>
        </div>

        <div className="mt-4 p-4 min-h-20 text-black bg-white rounded-md break-words">
          <h3 className="font-semibold mb-2">
            {mode === "Encrypt" ? "Result:" : "Decrypted Message:"}
          </h3>
          {result || (
            <span className="text-gray-500">
              {mode === "Encrypt"
                ? "Encrypted result will appear here"
                : "Decrypted result will appear here"}
            </span>
          )}
        </div>

        {algorithm === "rsa" && mode === "Encrypt" && result && (
          <div className="text-xs text-gray-600 mt-2">
            Note: RSA encryption produces comma-separated chunks
          </div>
        )}
      </div>
    </div>
  );
}

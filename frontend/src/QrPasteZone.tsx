import { useCallback, useEffect, useState } from "react";
import { decodeQrImage } from "./qr";

interface QrPasteZoneProps {
  onDecoded: (value: string) => boolean;
}

type ScanStatus = "ready" | "scanning" | "success" | "error";

export function QrPasteZone({ onDecoded }: QrPasteZoneProps) {
  const [status, setStatus] = useState<ScanStatus>("ready");
  const [message, setMessage] = useState("");

  const processImage = useCallback(async (file: Blob) => {
    setStatus("scanning");
    setMessage("正在识别二维码…");
    try {
      const value = await decodeQrImage(file);
      if (!value?.startsWith("otpauth://")) {
        setStatus("error");
        setMessage("未找到有效的 otpauth 二维码，请重试。");
        return;
      }
      if (onDecoded(value)) {
        setStatus("success");
        setMessage("二维码已识别，表单已自动填充。");
      } else {
        setStatus("error");
        setMessage("二维码内容不是有效的 TOTP 配置。");
      }
    } catch {
      setStatus("error");
      setMessage("无法读取这张二维码图片。");
    }
  }, [onDecoded]);

  useEffect(() => {
    const handlePaste = (event: ClipboardEvent) => {
      const item = Array.from(event.clipboardData?.items ?? [])
        .find((candidate) => candidate.kind === "file" && candidate.type.startsWith("image/"));
      const file = item?.getAsFile();
      if (!file) return;
      event.preventDefault();
      void processImage(file);
    };

    window.addEventListener("paste", handlePaste);
    return () => window.removeEventListener("paste", handlePaste);
  }, [processImage]);

  const handleDrop = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    const file = Array.from(event.dataTransfer.files).find((candidate) => candidate.type.startsWith("image/"));
    if (file) void processImage(file);
  };

  return (
    <div
      className={`paste-dropzone paste-${status}`}
      onDragOver={(event) => event.preventDefault()}
      onDrop={handleDrop}
      aria-label="粘贴二维码截图"
    >
      <span className="paste-dropzone-icon" aria-hidden="true">⌘</span>
      <strong>粘贴二维码截图</strong>
      <span>使用 Ctrl+V / Cmd+V 直接粘贴，也可以拖入图片</span>
      {status !== "ready" && <small>{message}</small>}
    </div>
  );
}

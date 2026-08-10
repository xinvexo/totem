import { useEffect, useRef, useState } from "react";
import jsQR from "jsqr";
import { X } from "lucide-react";
import { decodeQrImage } from "./qr";

interface QrScannerProps {
  onDecoded: (value: string) => void;
  onClose: () => void;
}

export function QrScanner({ onDecoded, onClose }: QrScannerProps) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [cameraError, setCameraError] = useState("");

  useEffect(() => {
    let stream: MediaStream | undefined;
    let timer: number | undefined;
    let stopped = false;

    const startCamera = async () => {
      if (!navigator.mediaDevices?.getUserMedia) {
        setCameraError("当前浏览器无法访问摄像头。");
        return;
      }
      try {
        stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: { ideal: "environment" } },
          audio: false,
        });
        if (stopped || !videoRef.current) return;
        videoRef.current.srcObject = stream;
        await videoRef.current.play();
        timer = window.setInterval(() => {
          const video = videoRef.current;
          const canvas = canvasRef.current;
          if (!video || !canvas || video.readyState < HTMLMediaElement.HAVE_CURRENT_DATA) return;
          const width = video.videoWidth;
          const height = video.videoHeight;
          if (!width || !height) return;
          canvas.width = width;
          canvas.height = height;
          const context = canvas.getContext("2d", { willReadFrequently: true });
          if (!context) return;
          context.drawImage(video, 0, 0, width, height);
          const image = context.getImageData(0, 0, width, height);
          const result = jsQR(image.data, width, height);
          if (result?.data.startsWith("otpauth://")) {
            onDecoded(result.data);
          }
        }, 240);
      } catch {
        setCameraError("摄像头权限被拒绝或摄像头正在使用中。你仍可以上传图片。");
      }
    };

    void startCamera();
    return () => {
      stopped = true;
      if (timer !== undefined) window.clearInterval(timer);
      stream?.getTracks().forEach((track) => track.stop());
    };
  }, [onDecoded]);

  const readImage = (file: File) => {
    void decodeQrImage(file)
      .then((value) => {
        if (value?.startsWith("otpauth://")) {
          onDecoded(value);
        } else {
          setCameraError("图片中未找到 otpauth 二维码。");
        }
      })
      .catch(() => setCameraError("无法读取这张图片。"));
  };

  return (
    <div className="qr-scanner" role="dialog" aria-modal="true" aria-label="扫描二维码">
      <div className="qr-scanner-head">
        <div>
          <p className="eyebrow">快速导入</p>
          <h3>扫描验证器二维码</h3>
        </div>
        <button className="icon-button" type="button" onClick={onClose} aria-label="关闭扫描器"><X size={16} aria-hidden="true" /></button>
      </div>
      <div className="camera-frame">
        <video ref={videoRef} muted playsInline />
        <span className="scan-corner scan-corner-tl" />
        <span className="scan-corner scan-corner-tr" />
        <span className="scan-corner scan-corner-bl" />
        <span className="scan-corner scan-corner-br" />
      </div>
      <canvas ref={canvasRef} className="visually-hidden" />
      <p className="scanner-hint">将摄像头对准二维码，或选择一张截图。</p>
      <label className="file-button">
        <span>选择二维码图片</span>
        <input
          type="file"
          accept="image/*"
          onChange={(event) => {
            const file = event.target.files?.[0];
            if (file) readImage(file);
            event.currentTarget.value = "";
          }}
        />
      </label>
      {cameraError && <p className="form-error">{cameraError}</p>}
    </div>
  );
}

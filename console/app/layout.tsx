import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "OwlWatch 콘솔",
  description: "시험 무결성 감독 콘솔",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="ko">
      <body>
        <div className="wrap">
          {children}
          <footer className="page">
            OwlWatch 는 부정행위를 판정하지 않는다. P0만이 확인된 사실이고, P1은 정황, P2는 참고다.
            처분은 사람과 위원회가 한다. 휴대폰·2차 기기·AI 안경은 범위 밖이다.
          </footer>
        </div>
      </body>
    </html>
  );
}

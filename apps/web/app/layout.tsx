export const metadata = { title: "OPT", description: "Offensive Pentest Orchestration Platform" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="vi">
      <body>{children}</body>
    </html>
  );
}

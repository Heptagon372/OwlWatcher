/** @type {import('next').NextConfig} */
export default {
  reactStrictMode: true,
  // 콘솔은 감독관만 쓰는 내부 도구다. 외부로 나가는 요청이 없어야 한다.
  poweredByHeader: false,
};

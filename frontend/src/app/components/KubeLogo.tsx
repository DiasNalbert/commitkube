export default function KubeLogo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 100 100" className={className} xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="kube-grad" x1="0" y1="0" x2="100" y2="100" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#10b981" />
          <stop offset="100%" stopColor="#fbbf24" />
        </linearGradient>
      </defs>
      <circle cx="50" cy="50" r="44" fill="none" stroke="url(#kube-grad)" strokeWidth="6" />
      <circle cx="50" cy="50" r="9" fill="url(#kube-grad)" />
      <g fill="url(#kube-grad)">
        {[0, 51.4, 102.9, 154.3, 205.7, 257.1, 308.6].map((deg, i) => (
          <rect key={i} x="47.5" y="12" width="5" height="27" rx="2.5" transform={`rotate(${deg} 50 50)`} />
        ))}
      </g>
    </svg>
  );
}

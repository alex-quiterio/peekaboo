// Falling code rain behind the panels. Purely decorative; still when the viewer prefers reduced motion.
(function rain() {
  const canvas = document.getElementById("rain"), ctx = canvas.getContext("2d");
  const glyphs = "アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワン0123456789";
  const size = 16;
  let drops = [];
  const resize = () => {
    canvas.width = innerWidth;
    canvas.height = innerHeight;
    drops = Array.from({ length: Math.ceil(innerWidth / size) }, () => Math.random() * (innerHeight / size));
  };
  const draw = () => {
    ctx.fillStyle = "rgba(0, 0, 0, 0.08)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.font = `${size}px ui-monospace, Menlo, monospace`;
    drops.forEach((y, i) => {
      ctx.fillStyle = Math.random() > 0.96 ? "#d6ffe4" : "#00ff66";
      ctx.fillText(glyphs[Math.floor(Math.random() * glyphs.length)], i * size, y * size);
      drops[i] = y * size > canvas.height && Math.random() > 0.975 ? 0 : y + 1;
    });
  };
  addEventListener("resize", resize);
  resize();
  for (let i = 0; i < 40; i++) draw();
  if (!matchMedia("(prefers-reduced-motion: reduce)").matches) setInterval(draw, 60);
})();

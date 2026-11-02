// Aplica o tema salvo (claro/escuro/sistema) antes da página aparecer, para não piscar.
// Carregado de forma síncrona no <head> de todas as páginas.
(function () {
  try {
    var t = localStorage.getItem('ipv6-tema');
    if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
  } catch (e) { /* armazenamento bloqueado: segue o tema do sistema */ }
})();

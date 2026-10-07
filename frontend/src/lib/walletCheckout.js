let checkoutScript;
function loadCheckout() {
  if (window.Razorpay) return Promise.resolve();
  if (!checkoutScript) {
    checkoutScript = new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = 'https://checkout.razorpay.com/v1/checkout.js';
      script.onload = () => window.Razorpay ? resolve() : reject(new Error('Payment checkout unavailable'));
      script.onerror = () => { script.remove(); reject(new Error('Unable to load payment checkout')); };
      document.head.appendChild(script);
    }).catch(error => { checkoutScript = null; throw error; });
  }
  return checkoutScript;
}

export async function openWalletCheckout(order) {
  await loadCheckout();
  if (order.gateway !== 'razorpay' || !order.key_id || !order.order_id) {
    throw new Error('Payment checkout unavailable');
  }
  return new Promise(resolve => {
    const checkout = new window.Razorpay({
      key: order.key_id, order_id: order.order_id,
      amount: Math.round(Number(order.amount) * 100), currency: order.currency,
      name: 'UGCad', description: 'Add funds to wallet',
      handler: result => resolve(result),
      modal: { ondismiss: () => resolve(null) },
    });
    checkout.open();
  });
}

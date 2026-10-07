import { openWalletCheckout } from './walletCheckout';

const order = { gateway: 'razorpay', key_id: 'key', order_id: 'order_1', amount: 2500, currency: 'INR' };
afterEach(() => { delete window.Razorpay; });

test('opens checkout using the backend order and converts rupees to paise', async () => {
  const payment = { razorpay_order_id: 'order_1', razorpay_payment_id: 'pay_1', razorpay_signature: 'signature' };
  let options;
  window.Razorpay = jest.fn(config => {
    options = config;
    return { open: () => config.handler(payment) };
  });
  await expect(openWalletCheckout(order)).resolves.toEqual(payment);
  expect(options.order_id).toBe('order_1');
  expect(options.amount).toBe(250000);
});

test('cancelling returns without payment verification details', async () => {
  window.Razorpay = jest.fn(config => ({ open: () => config.modal.ondismiss() }));
  await expect(openWalletCheckout(order)).resolves.toBeNull();
});

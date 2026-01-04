export default function allowPurchaseIfAmountLeq(params, input) {
  const { max_amount } = params;
  const { cart_total_amount } = input;

  if (typeof cart_total_amount !== "number" || typeof max_amount !== "number") {
    return false;
  }

  return cart_total_amount <= max_amount;
}

export default function allowPurchaseIfAmountLeq(params, input) {
  const { max_amount } = params;
  const { total_amount } = input;

  if (typeof total_amount !== "number" || typeof max_amount !== "number") {
    return false;
  }

  return total_amount <= max_amount;
}

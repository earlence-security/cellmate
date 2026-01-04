export default function allowOrderReturnOrExchangeIfDelivered(params, input) {
  const { orderStatus } = input;

  if (typeof orderStatus !== "string") {
    return false;
  }

  return orderStatus === "delivered";
}

export default function allowOrderModificationOrCancellationIfPending(
  params,
  input
) {
  const { orderStatus } = input;

  if (typeof orderStatus !== "string") {
    return false;
  }

  return orderStatus === "pending";
}


export async function onRequestPost(context: any) {
    const { id } = await context.request.json();

    return new Response(JSON.stringify({
        id,
        timestamp: new Date(),
        status: "Analyzed",
        verdict: "Safe",
        downloadLink: `/reports/${id}.pdf`
    }), {
        headers: { "Content-Type": "application/json" }
    });
}

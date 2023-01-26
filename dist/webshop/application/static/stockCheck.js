document.getElementById("stockForm").onsubmit = async (e) => {
    e.preventDefault();

    let response = await fetch('/item/stock', {
        method: 'POST',
        body: new FormData(stockForm)
    });

    let result = await response.text();

    document.getElementById("stockCheckResult").innerHTML = result;
}
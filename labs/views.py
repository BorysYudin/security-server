from django.http import HttpResponse
from django.template import loader

from main import Rand, MD5


def lab1(request):
    template = loader.get_template('labs/lab1.html')

    if request.method == "GET":
        return HttpResponse(template.render({}, request))

    A, X0, C, M, count = list(map(int, [
        request.POST.get("lab1_a"),
        request.POST.get("lab1_x0"),
        request.POST.get("lab1_c"),
        request.POST.get("lab1_m"),
        request.POST.get("lab1_count"),
    ]))
    rand = Rand(A, X0, C, M)

    generated_sequence = [rand() for _ in range(count)]

    with open("random_sequence.csv", "w+") as file_:
        file_.write(",".join(map(str, generated_sequence)))

    context = {
        "lab1_result": {
            "numbers": generated_sequence if len(generated_sequence) <= 100 else "Sequence is to big",
            "period": Rand.get_sequence_period(generated_sequence),
        }
    }

    return HttpResponse(template.render(context, request))


def string_hash(request):
    template = loader.get_template('labs/lab2.html')

    if request.method == "GET":
        return HttpResponse(template.render({}, request))

    context = {
        "string_hash": MD5(request.POST["string"]).generate()
    }
    return HttpResponse(template.render(context, request))


def file_hash(request):
    template = loader.get_template('labs/lab2_file_hash.html')

    if request.method == "GET":
        return HttpResponse(template.render({}, request))

    file_hash_ = MD5(request.FILES["file"].read()).generate()

    with open("file_hash.txt", "w") as f:
        f.write(file_hash_)

    context = {
        "file_hash": file_hash_
    }
    return HttpResponse(template.render(context, request))


def integrity_check(request):
    template = loader.get_template('labs/lab2_file_integrity.html')

    if request.method == "GET":
        return HttpResponse(template.render({}, request))

    check_file_data = request.FILES["file"].read()
    file_with_hash = request.FILES.get("file_with_hash")

    if file_with_hash:
        hash_data = file_with_hash.read().decode("utf-8")
    else:
        hash_data = request.POST["hash_string"]

    file_hash_ = MD5(check_file_data).generate()

    integrity_value = "File is NOT valid."
    integrity_color = "red"
    if hash_data == file_hash_:
        integrity_value = "File is valid."
        integrity_color = "green"

    context = {
        "file_hash": file_hash_,
        "integrity_value": integrity_value,
        "integrity_color": integrity_color,
    }
    return HttpResponse(template.render(context, request))

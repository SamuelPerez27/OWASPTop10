import datetime

# Obtener la hora actual del sistema
now = datetime.datetime.now()

# Mostrar la hora actual en formato HH:MM:SS
current_time = now.strftime("%H:%M:%S")
print("Hora actual:", now)

# -*- coding: utf-8 -*-
"""
Created on Thu Oct 21 16:43:23 2021

@author: jrcar
"""
# -*- coding: utf-8 -*-

#Mecanismo de detección de error en IP
#Mecanismos de Checksum IP de acuerdo con RFC 791 y COMER
#Programó: Roberto Cárdenas

#DATOS DE ENTRADA
#Datos de encabezado ip para calcular checksum en el transmisor
ip_tx = ("45 00 00 34 42 a3 40 00 80 06 00 00 c0 a8 00 0b a8 b0 05 45")

#Encabezado ip con checksum generado en tx de acuerdo a COMER
ip_rx = ("45 00 00 34 42 a3 40 00 80 06 49 78 c0 a8 00 0b a8 b0 05 45")

#Encabezado ip con checksum generado en tx de acuerdo a RFC 791
#ip_rx = ("45 00 00 34 42 a3 40 00 80 06 b6 87 c0 a8 00 0b a8 b0 05 45")

#SUBRUTINAS
#Diccionario para encontrar complemento a 1
comp1 = {"0":"f","1":"e","2":"d","3":"c","4":"b","5":"a","6":"9","7":"8",
        "8":"7","9":"6","a":"5","b":"4","c":"3","d":"2","e":"1","f":"0"}

#Quitar los espacios del ip_tx/ip_rx
def obtener_datos_limpios(ip_check):
    global ip_p
    ip_p = []
    for j in range(0,len(ip_check),1):
        if ip_check[j] != " ":
            ip_p.append(ip_check[j])  
    return ip_p

#Suma de los datos en 16 bits
def suma_en_16_bits(suma_16):
    global hsuma 
    hsuma = hex(0)
    for i in range(0,len(suma_16),4):
        temp = suma_16[i] + suma_16[i+1] + suma_16[i+2] + suma_16[i+3] 
        suma  = int(str(temp),16) + int(hsuma,16)
        hsuma = hex(suma) 
    suma = suma + 2**20
    hsuma = hex(suma)
    return hsuma

#Suma en complemento a 1
def suma_en_complemento_a_1(hsum):
    global hscompl
    hscompl = ""
    lhs = len(hsum)
    temp1 = hsum[lhs-4] + hsum[lhs-3] + hsum[lhs-2] + hsum[lhs-1]
    temp2 = hsum[lhs-5]
    scompl = int(str(temp1),16) + int(str(temp2),16) + 2**16
    hscompl = hex(scompl)
    return hscompl

#Complemento a 1 de la suma en complemento a 1    
def complemento_a_1_de_suma(hsc):
    global check
    check = []
    lh = len(hsc)
    cp1 = str(hsc[lh-4] + hsc[lh-3] + hsc[lh-2] + hsc[lh-1])
    for i in cp1:
       if i in comp1:
          check.append(comp1[i])
    return check

#Generación del checksum
def generar_checksum(chk, hscp):
    checksum = hscp[0] + hscp[1] + chk[0] + chk[1] + chk[2] + chk[3]
    print("Con los datos {},".format(ip_tx))
    print("el transmisor generó el checksum {}.".format(checksum))

#Detección de error en el receptor
def detectar_error(hsc):
    print("Con los datos {},".format(ip_rx))
    print_error = hsc[0] + hsc[1] + hsc[3] + hsc[4] + hsc[5] + hsc[6]
    if print_error == "0xffff":
        print("El receptor ha calculado un checksum igual a {}, "
            "por tanto ha recibido un 1.".format(print_error))
    else:
        print("El receptor ha calculado un ckecksum igual a {}, "
            "por tanto ha recibido un 0.".format(print_error))

#ALGORITMOS DE CALCULO DE CHECKSUM EN TX Y RX
def main():
    #generación del checksum en el transmisor
    obtener_datos_limpios(ip_tx)
    suma_en_16_bits(ip_p)
    suma_en_complemento_a_1(hsuma)
    complemento_a_1_de_suma(hscompl)
    generar_checksum(check, hscompl)

    #Detectar error en el receptor
    obtener_datos_limpios(ip_rx)
    suma_en_16_bits(ip_p)
    suma_en_complemento_a_1(hsuma)
    detectar_error(hscompl)

#Punto de entrada del programa
if __name__ == '__main__':
	main()

#Conclusión: tx ha enviado un 0 si el resultado del cálculo de checksum 
#en rx es 0x6d0f. Si el resultado en rx es 0xffff tx ha enviado un 1.
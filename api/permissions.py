from rest_framework import permissions

class IsOwner(permissions.BasePermission):
       message = "Usuario no es el propietario"

       def has_object_permission(self, request, view, obj):
              print(obj.owner)
              print(request.user)
              if request.method in permissions.SAFE_METHODS:
                     return True
              return request.user == obj.owner
